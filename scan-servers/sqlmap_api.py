import subprocess
import shutil
import os
import tempfile
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from security import sanitize_target, sanitize_options
from runner import run_streaming

app = FastAPI(title="SQLmap API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DEFAULT_OPTIONS = "--batch --level=2 --risk=2"


class ScanRequest(BaseModel):
    target: str
    options: str = ""
    stealth: bool = True


@app.get("/health")
def health():
    sqlmap_path = shutil.which("sqlmap")
    return {
        "status": "ok",
        "tool": "sqlmap",
        "installed": sqlmap_path is not None,
        "path": sqlmap_path,
    }


@app.post("/scan")
def run_sqlmap(req: ScanRequest):
    try:
        target = sanitize_target(req.target)
        raw_opts = req.options.strip() if req.options.strip() else DEFAULT_OPTIONS
        options = sanitize_options(raw_opts)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    sqlmap_path = shutil.which("sqlmap")
    if not sqlmap_path:
        raise HTTPException(
            status_code=500,
            detail="sqlmap is not installed. Install it with: sudo apt install sqlmap",
        )

    url = target if "://" in target else f"http://{target}"

    safe_opts = ["--batch"]
    for o in options.split():
        if o == "--batch":
            continue
        if o.startswith("--") and len(o) < 60:
            safe_opts.append(o)

    opts_str = " ".join(safe_opts)
    if "--level" not in opts_str:
        safe_opts.append("--level=2")
    if "--risk" not in opts_str:
        safe_opts.append("--risk=2")

    has_query = "?" in url and "=" in url.split("?", 1)[1]
    if not has_query:
        if "--forms" not in opts_str:
            safe_opts.append("--forms")
        if "--crawl" not in opts_str:
            safe_opts.append("--crawl=2")
        if "--smart" not in opts_str:
            safe_opts.append("--smart")

    if "--random-agent" not in opts_str:
        safe_opts.append("--random-agent")
    if "--threads" not in opts_str:
        safe_opts.append("--threads=4")

    if req.stealth and "--delay" not in opts_str:
        safe_opts.append("--delay=1")

    timeout = 1200

    with tempfile.TemporaryDirectory() as tmpdir:
        cmd = [sqlmap_path, "-u", url, "--output-dir", tmpdir] + safe_opts
        try:
            output, rc = run_streaming(cmd, timeout=timeout, label="SQLMAP")
            if not output.strip():
                output = "sqlmap produced no output."
        except Exception as e:
            output = f"Error running sqlmap: {type(e).__name__}: {str(e)}"

    return {
        "tool": "sqlmap",
        "target": target,
        "command": " ".join(cmd),
        "output": output,
        "status": "completed",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)
