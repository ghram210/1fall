import subprocess
import shutil
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from security import sanitize_target, sanitize_options, extract_hostname

app = FastAPI(title="Nmap API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    target: str
    options: str = "-sV -T4 --top-ports 1000"


@app.get("/health")
def health():
    return {"status": "ok", "tool": "nmap"}


@app.post("/scan")
def run_nmap(req: ScanRequest):
    try:
        target = sanitize_target(req.target)
        options = sanitize_options(req.options)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    nmap_path = shutil.which("nmap")
    if not nmap_path:
        raise HTTPException(
            status_code=500,
            detail="Tool nmap is not installed on the system",
        )

    hostname = extract_hostname(target)
    safe_options = [o for o in options.split() if not o.startswith("-") or len(o) < 20]

    cmd = [nmap_path] + safe_options + [hostname]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
        output = result.stdout or result.stderr or "No output"
    except subprocess.TimeoutExpired:
        output = "Scan timed out after 120 seconds"
    except Exception as e:
        output = f"Error running nmap: {str(e)}"

    return {
        "tool": "nmap",
        "target": target,
        "output": output,
        "status": "completed",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
