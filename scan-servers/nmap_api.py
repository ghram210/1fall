import subprocess
import shutil
import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from security import sanitize_target, sanitize_options, extract_hostname
from runner import run_streaming

app = FastAPI(title="Nmap API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DEFAULT_OPTIONS_STEALTH = "-sV -T2 --top-ports 1000 --script=vuln,vulners,http-headers,http-methods,ssl-cert,banner"
DEFAULT_OPTIONS_NORMAL  = "-sV -T4 --top-ports 1000 --script=vuln,vulners,http-headers,http-methods,ssl-cert,banner"

TIMEOUT_STEALTH = 1800
TIMEOUT_NORMAL  = 900


class ScanRequest(BaseModel):
    target: str
    options: str = ""
    stealth: bool = True


@app.get("/health")
def health():
    nmap_path = shutil.which("nmap")
    return {
        "status": "ok",
        "tool": "nmap",
        "installed": nmap_path is not None,
        "path": nmap_path,
        "running_as_root": os.geteuid() == 0,
    }


@app.post("/scan")
def run_nmap(req: ScanRequest):
    try:
        target = sanitize_target(req.target)
        default_opts = DEFAULT_OPTIONS_STEALTH if req.stealth else DEFAULT_OPTIONS_NORMAL
        raw_opts = req.options.strip() if req.options.strip() else default_opts
        options = sanitize_options(raw_opts)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    nmap_path = shutil.which("nmap")
    if not nmap_path:
        raise HTTPException(
            status_code=500,
            detail="nmap is not installed. Install it with: sudo apt install nmap",
        )

    hostname = extract_hostname(target)
    is_root = os.geteuid() == 0

    safe_options = [o for o in options.split() if not o.startswith("-") or len(o) < 60]

    if not is_root:
        if "-sS" in safe_options:
            safe_options = [o for o in safe_options if o != "-sS"]
            safe_options.insert(0, "-sT")
        elif not any(o.startswith("-s") for o in safe_options):
            safe_options.insert(0, "-sT")

    if "-Pn" not in safe_options:
        safe_options.append("-Pn")

    cmd = [nmap_path] + safe_options + [hostname]

    timeout = TIMEOUT_STEALTH if req.stealth else TIMEOUT_NORMAL

    try:
        output, rc = run_streaming(cmd, timeout=timeout, label="NMAP")
        if not output.strip():
            output = "No output from nmap. The host may be offline or blocking scans."
    except Exception as e:
        output = f"Error running nmap: {type(e).__name__}: {str(e)}"

    return {
        "tool": "nmap",
        "target": target,
        "command": " ".join(cmd),
        "output": output,
        "status": "completed",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
