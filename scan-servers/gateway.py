import os
import uuid
import asyncio
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, HTTPException, Header, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from config import (
    SUPABASE_URL, SUPABASE_SERVICE_KEY,
    NMAP_URL, NIKTO_URL, SQLMAP_URL, FFUF_URL,
)
from security import sanitize_target, sanitize_options
from auth import get_admin_user

app = FastAPI(title="Scan Gateway", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

TOOL_SERVERS = {
    "NMAP": NMAP_URL,
    "NIKTO": NIKTO_URL,
    "SQLMAP": SQLMAP_URL,
    "FFUF": FFUF_URL,
}

SUPABASE_HEADERS = {
    "apikey": SUPABASE_SERVICE_KEY,
    "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
    "Content-Type": "application/json",
    "Prefer": "return=representation",
}


class ScanRequest(BaseModel):
    name: str
    target: str
    tool: str
    description: str = ""
    options: str = ""
    stealth: bool = True   # default: stealth ON


async def update_scan_in_supabase(scan_id: str, data: dict):
    async with httpx.AsyncClient() as client:
        await client.patch(
            f"{SUPABASE_URL}/rest/v1/scan_results",
            params={"id": f"eq.{scan_id}"},
            headers=SUPABASE_HEADERS,
            json=data,
            timeout=15,
        )


async def run_scan_background(scan_id: str, target: str, tool: str, options: str, stealth: bool = True):
    tool_url = TOOL_SERVERS.get(tool)
    if not tool_url:
        await update_scan_in_supabase(scan_id, {
            "status": "failed",
            "raw_output": f"Unknown tool: {tool}",
            "completed_at": datetime.now(timezone.utc).isoformat(),
        })
        return

    # Stealth scans can take up to 60 min; normal up to 45 min
    http_timeout = 3700 if stealth else 2700

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{tool_url}/scan",
                json={"target": target, "options": options, "stealth": stealth},
                timeout=http_timeout,
            )
        
        if resp.status_code == 200:
            result = resp.json()
            raw_output = result.get("output", "No output")
        else:
            raw_output = f"Tool server error: {resp.status_code} {resp.text}"

    except httpx.ConnectError:
        raw_output = f"Cannot connect to {tool} server at {tool_url}. Is it running?"
    except httpx.TimeoutException:
        raw_output = f"{tool} scan timed out"
    except Exception as e:
        raw_output = f"Unexpected error: {str(e)}"

    await update_scan_in_supabase(scan_id, {
        "status": "completed",
        "raw_output": raw_output,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": raw_output.lower().count("finding") + raw_output.lower().count("vulnerable"),
    })


@app.get("/health")
def health():
    return {"status": "ok", "service": "gateway"}


@app.post("/scan")
async def start_scan(
    req: ScanRequest,
    background_tasks: BackgroundTasks,
    authorization: str = Header(None),
):
    user = await get_admin_user(authorization)

    if req.tool not in TOOL_SERVERS and req.tool != "FULL":
        raise HTTPException(status_code=400, detail=f"Unknown tool: {req.tool}. Use: {list(TOOL_SERVERS.keys())} or FULL")

    try:
        target = sanitize_target(req.target)
        options = sanitize_options(req.options) if req.options else ""
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    scan_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    scan_data = {
        "id": scan_id,
        "name": req.name[:200],
        "target": target,
        "tool": req.tool,
        "description": req.description[:500] if req.description else "",
        "options": options,
        "status": "running",
        "started_at": now,
        "user_id": user["id"],
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "total_findings": 0,
    }

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{SUPABASE_URL}/rest/v1/scan_results",
            headers=SUPABASE_HEADERS,
            json=scan_data,
            timeout=15,
        )

    if resp.status_code not in (200, 201):
        raise HTTPException(status_code=500, detail=f"Failed to create scan record: {resp.text}")

    if req.tool == "FULL":
        for tool_name in TOOL_SERVERS:
            sub_id = str(uuid.uuid4())
            sub_data = {**scan_data, "id": sub_id, "name": f"{req.name} [{tool_name}]", "tool": tool_name}
            async with httpx.AsyncClient() as client:
                await client.post(
                    f"{SUPABASE_URL}/rest/v1/scan_results",
                    headers=SUPABASE_HEADERS,
                    json=sub_data,
                    timeout=15,
                )
            background_tasks.add_task(run_scan_background, sub_id, target, tool_name, options, req.stealth)

        await update_scan_in_supabase(scan_id, {
            "status": "completed",
            "raw_output": "Full scan dispatched to all tool servers. See individual scans below.",
            "completed_at": now,
        })
    else:
        background_tasks.add_task(run_scan_background, scan_id, target, req.tool, options, req.stealth)

    return {
        "scan_id": scan_id,
        "status": "running",
        "message": f"Scan started for {target} using {req.tool}",
    }


@app.get("/scan/{scan_id}")
async def get_scan_status(scan_id: str, authorization: str = Header(None)):
    await get_admin_user(authorization)

    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{SUPABASE_URL}/rest/v1/scan_results",
            params={"id": f"eq.{scan_id}", "select": "*"},
            headers=SUPABASE_HEADERS,
            timeout=15,
        )

    if resp.status_code != 200 or not resp.json():
        raise HTTPException(status_code=404, detail="Scan not found")

    return resp.json()[0]


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
