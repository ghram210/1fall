import os
import uuid
import asyncio
import re
import traceback
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, HTTPException, Header, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
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
    expose_headers=["*"],
)


def _cors_headers(request: Request) -> dict:
    origin = request.headers.get("origin", "*")
    return {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Methods": "*",
        "Access-Control-Allow-Headers": "*",
        "Vary": "Origin",
    }


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail},
        headers=_cors_headers(request),
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    tb = traceback.format_exc()
    print(f"[gateway] UNHANDLED ERROR on {request.method} {request.url.path}:\n{tb}",
          flush=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": f"{type(exc).__name__}: {str(exc)}",
            "path": request.url.path,
        },
        headers=_cors_headers(request),
    )

TOOL_SERVERS = {
    "NMAP": NMAP_URL,
    "NIKTO": NIKTO_URL,
    "SQLMAP": SQLMAP_URL,
    "FFUF": FFUF_URL,
}

TOOL_DEFAULT_OPTIONS = {
    "NMAP":   "",
    "NIKTO":  "",
    "SQLMAP": "",
    "FFUF":   "",
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
    stealth: bool = True


def count_findings(tool: str, output: str) -> int:
    """
    Pull the finding count from a tool's formatted output. Each tool now emits
    a dedicated header line; we read that first. If the formatted header isn't
    present (e.g. a raw passthrough), fall back to the original heuristic.
    """
    if not output:
        return 0
    tool = tool.upper()

    if tool == "NMAP":
        return len(re.findall(r'\d+/tcp\s+open', output, re.IGNORECASE))

    if tool == "NIKTO":
        # New formatted output: "Unique findings: N  (deduplicated from ...)"
        m = re.search(r'Unique findings:\s*(\d+)', output)
        if m:
            return int(m.group(1))
        # Legacy nikto raw "X item(s) reported"
        m = re.search(r'(\d+)\s+item\(s\)\s+reported', output, re.IGNORECASE)
        if m:
            return int(m.group(1))
        # Last-resort fallback for raw "+ " lines
        meta_prefixes = (
            "+ Target ", "+ Start Time", "+ End Time", "+ Server:",
            "+ Host:", "+ Site Link", "+ Root page",
            "+ /robots.txt", "+ No CGI", "+ Scan terminated",
            "+ 1 host(s) tested",
        )
        count = 0
        for line in output.splitlines():
            if line.startswith("+ ") and not line.startswith(meta_prefixes):
                if "sent cookie:" in line.lower():
                    continue
                count += 1
        return count

    if tool == "SQLMAP":
        patterns = [
            r"parameter\s+'[^']+'\s+is\s+vulnerable",
            r"appears to be '[^']+' injectable",
            r"is vulnerable\.",
            r"^Parameter:\s",
            r"sqlmap identified the following injection point",
        ]
        total = 0
        for p in patterns:
            total += len(re.findall(p, output, re.IGNORECASE | re.MULTILINE))
        return total

    if tool == "FFUF":
        # New formatted output: "Real findings: N  (filtered out ...)"
        m = re.search(r'Real findings:\s*(\d+)', output)
        if m:
            return int(m.group(1))
        # Legacy
        m = re.search(r'Total findings:\s*(\d+)', output)
        if m:
            return int(m.group(1))
        return len(re.findall(r'Size:\d+', output))

    return output.lower().count("finding") + output.lower().count("vulnerable")


async def update_scan_in_supabase(scan_id: str, data: dict):
    try:
        async with httpx.AsyncClient() as client:
            await client.patch(
                f"{SUPABASE_URL}/rest/v1/scan_results",
                params={"id": f"eq.{scan_id}"},
                headers=SUPABASE_HEADERS,
                json=data,
                timeout=15,
            )
    except Exception as e:
        print(f"[gateway] Failed to update scan {scan_id}: {e}")


async def _heartbeat(scan_id: str, tool: str, started_at: float, stop_event: asyncio.Event):
    """
    While the scan is running, update Supabase every 60 seconds with a
    "still running" marker so the UI can detect stale scans (last heartbeat
    too old → server probably died).
    """
    while not stop_event.is_set():
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=60)
            return
        except asyncio.TimeoutError:
            pass
        elapsed = int(asyncio.get_event_loop().time() - started_at)
        await update_scan_in_supabase(scan_id, {
            "raw_output": (
                f"[{tool}] Scan in progress…\n"
                f"Elapsed: {elapsed // 60}m {elapsed % 60}s\n"
                f"Last heartbeat: {datetime.now(timezone.utc).isoformat()}\n"
                f"\n(Live results will appear here when the tool finishes. "
                f"If this message stops updating for more than 5 minutes, "
                f"the scan server has likely been interrupted.)"
            ),
        })


async def run_scan_background(
    scan_id: str, target: str, tool: str, options: str, stealth: bool = True
):
    tool_url = TOOL_SERVERS.get(tool)
    if not tool_url:
        await update_scan_in_supabase(scan_id, {
            "status": "failed",
            "raw_output": f"Unknown tool: {tool}",
            "completed_at": datetime.now(timezone.utc).isoformat(),
        })
        return

    effective_options = options.strip() if options.strip() else TOOL_DEFAULT_OPTIONS.get(tool, "")

    http_timeout = 3700 if stealth else 2700

    stop_event = asyncio.Event()
    hb_task = asyncio.create_task(
        _heartbeat(scan_id, tool, asyncio.get_event_loop().time(), stop_event)
    )

    raw_output = ""
    final_status = "completed"
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{tool_url}/scan",
                json={"target": target, "options": effective_options, "stealth": stealth},
                timeout=http_timeout,
            )

        if resp.status_code == 200:
            result = resp.json()
            raw_output = result.get("output", "No output returned")
        else:
            raw_output = (
                f"Tool server returned error {resp.status_code}.\n"
                f"Response: {resp.text[:500]}"
            )
            final_status = "failed"

    except httpx.ConnectError:
        raw_output = (
            f"[ERROR] Cannot connect to {tool} server at {tool_url}.\n"
            f"Make sure start.sh is running and the tool server started successfully.\n"
            f"Check logs/{tool.lower()}.log for details."
        )
        final_status = "failed"
    except httpx.TimeoutException:
        raw_output = f"[TIMEOUT] {tool} scan timed out after {http_timeout // 60} minutes."
        final_status = "failed"
    except Exception as e:
        raw_output = f"[UNEXPECTED ERROR] {type(e).__name__}: {str(e)}"
        final_status = "failed"
    finally:
        stop_event.set()
        try:
            await asyncio.wait_for(hb_task, timeout=2)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            pass

    findings = count_findings(tool, raw_output)

    await update_scan_in_supabase(scan_id, {
        "status": final_status,
        "raw_output": raw_output,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": findings,
    })


async def reconcile_stale_scans():
    """
    On gateway startup, mark any scans still 'running' from a previous
    process as 'failed (interrupted)'. We use a generous 6h ceiling — the
    longest legitimate scan (stealth nikto) is ~25 min, so anything beyond
    that is definitely from a dead process.
    """
    cutoff_minutes = 30
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{SUPABASE_URL}/rest/v1/scan_results",
                params={
                    "status": "eq.running",
                    "select": "id,name,tool,started_at,raw_output",
                },
                headers=SUPABASE_HEADERS,
                timeout=15,
            )
        if resp.status_code != 200:
            print(f"[gateway] Could not fetch stale scans: {resp.status_code}")
            return

        rows = resp.json()
        now = datetime.now(timezone.utc)
        marked = 0
        for row in rows:
            started_str = row.get("started_at") or ""
            try:
                started = datetime.fromisoformat(started_str.replace("Z", "+00:00"))
            except Exception:
                continue
            age_min = (now - started).total_seconds() / 60
            if age_min < cutoff_minutes:
                continue

            existing = row.get("raw_output") or ""
            note = (
                f"\n\n[gateway] Scan was interrupted by server restart "
                f"(detected on startup, age {int(age_min)} minutes).\n"
                f"Marked as failed automatically."
            )
            await update_scan_in_supabase(row["id"], {
                "status": "failed",
                "raw_output": (existing + note).strip(),
                "completed_at": now.isoformat(),
            })
            marked += 1

        if marked:
            print(f"[gateway] Reconciled {marked} stale running scan(s) → failed")
    except Exception as e:
        print(f"[gateway] reconcile_stale_scans error: {e}")


@app.on_event("startup")
async def _on_startup():
    await reconcile_stale_scans()


@app.get("/health")
def health():
    tool_status = {}
    return {"status": "ok", "service": "gateway", "tools": list(TOOL_SERVERS.keys())}


@app.get("/tool-health")
async def tool_health():
    results = {}
    for name, url in TOOL_SERVERS.items():
        try:
            async with httpx.AsyncClient() as client:
                r = await client.get(f"{url}/health", timeout=3)
            results[name] = "ok" if r.status_code == 200 else f"error:{r.status_code}"
        except Exception as e:
            results[name] = f"unreachable: {str(e)}"
    return results


@app.post("/scan")
async def start_scan(
    req: ScanRequest,
    background_tasks: BackgroundTasks,
    authorization: str = Header(None),
):
    user = await get_admin_user(authorization)

    if req.tool not in TOOL_SERVERS and req.tool != "FULL":
        raise HTTPException(
            status_code=400,
            detail=f"Unknown tool: {req.tool}. Use: {list(TOOL_SERVERS.keys())} or FULL",
        )

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

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{SUPABASE_URL}/rest/v1/scan_results",
                headers=SUPABASE_HEADERS,
                json=scan_data,
                timeout=15,
            )
    except httpx.HTTPError as e:
        raise HTTPException(
            status_code=502,
            detail=(
                f"Cannot reach Supabase at {SUPABASE_URL}: "
                f"{type(e).__name__}: {str(e)}"
            ),
        )

    if resp.status_code not in (200, 201):
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create scan record (Supabase {resp.status_code}): {resp.text[:500]}",
        )

    if req.tool == "FULL":
        for tool_name in TOOL_SERVERS:
            sub_id = str(uuid.uuid4())
            sub_data = {
                **scan_data,
                "id": sub_id,
                "name": f"{req.name} [{tool_name}]",
                "tool": tool_name,
            }
            async with httpx.AsyncClient() as client:
                await client.post(
                    f"{SUPABASE_URL}/rest/v1/scan_results",
                    headers=SUPABASE_HEADERS,
                    json=sub_data,
                    timeout=15,
                )
            background_tasks.add_task(
                run_scan_background, sub_id, target, tool_name, options, req.stealth
            )

        await update_scan_in_supabase(scan_id, {
            "status": "completed",
            "raw_output": "Full scan dispatched. See individual tool scans below.",
            "completed_at": now,
        })
    else:
        background_tasks.add_task(
            run_scan_background, scan_id, target, req.tool, options, req.stealth
        )

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
    uvicorn.run(app, host="0.0.0.0", port=8090)
