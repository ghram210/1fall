import subprocess
import shutil
import os
import tempfile
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from security import sanitize_target, sanitize_options

app = FastAPI(title="SQLmap API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    target: str
    options: str = "--batch --level=1 --risk=1"


@app.get("/health")
def health():
    return {"status": "ok", "tool": "sqlmap"}


@app.post("/scan")
def run_sqlmap(req: ScanRequest):
    try:
        target = sanitize_target(req.target)
        options = sanitize_options(req.options)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    sqlmap_path = shutil.which("sqlmap")
    if not sqlmap_path:
        raise HTTPException(
            status_code=500,
            detail="Tool sqlmap is not installed on the system",
        )

    url = target if "://" in target else f"http://{target}"
    safe_opts = []
    for o in options.split():
        if o.startswith("--") and "=" in o and len(o) < 50:
            safe_opts.append(o)
        elif o in ["--batch", "--forms", "--crawl", "--dbs", "--tables"]:
            safe_opts.append(o)

    cmd = [sqlmap_path, "-u", url, "--batch"] + safe_opts

    with tempfile.TemporaryDirectory() as tmpdir:
        cmd.extend(["--output-dir", tmpdir])
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
            output = f"Error running sqlmap: {str(e)}"

    return {
        "tool": "sqlmap",
        "target": target,
        "output": output,
        "status": "completed",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)
