import shutil
import urllib.parse
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

TIMEOUT_STEALTH = 1200
TIMEOUT_NORMAL  = 600

PROTECTED_FLAGS = {
    "--level", "--risk", "--threads", "--timeout",
    "--retries", "--time-sec", "--technique", "--batch",
    "--delay",
}


class ScanRequest(BaseModel):
    target: str
    options: str = ""
    stealth: bool = True


def _base_flag(opt: str) -> str:
    return opt.split("=")[0]


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
        raw_opts = req.options.strip() if req.options.strip() else ""
        options = sanitize_options(raw_opts) if raw_opts else ""
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    sqlmap_path = shutil.which("sqlmap")
    if not sqlmap_path:
        raise HTTPException(
            status_code=500,
            detail="sqlmap is not installed. Install it with: sudo apt install sqlmap",
        )

    url = target if "://" in target else f"http://{target}"

    parsed = urllib.parse.urlparse(url)
    has_query = bool(parsed.query) and "=" in parsed.query

    if req.stealth:
        cmd = [
            sqlmap_path,
            "-u", url,
            "--batch",
            "--random-agent",
            "--level=3",
            "--risk=2",
            "--threads=2",
            "--timeout=30",
            "--retries=1",
            "--time-sec=7",
            "--technique=BEUSTQ",
            "--delay=1",
        ]
    else:
        cmd = [
            sqlmap_path,
            "-u", url,
            "--batch",
            "--random-agent",
            "--level=3",
            "--risk=2",
            "--threads=5",
            "--timeout=30",
            "--retries=1",
            "--time-sec=5",
            "--technique=BEUSTQ",
        ]

    if has_query:
        cmd.append("--dbs")
    else:
        cmd.append("--forms")

    if options:
        protected_bases = {_base_flag(o) for o in cmd}
        for o in options.split():
            if not ((o.startswith("--") or o.startswith("-")) and len(o) < 60):
                continue
            base = _base_flag(o)
            if base in PROTECTED_FLAGS or base in protected_bases:
                continue
            cmd.append(o)

    timeout = TIMEOUT_STEALTH if req.stealth else TIMEOUT_NORMAL

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
