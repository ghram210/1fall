import subprocess
import shutil
import urllib.parse
import random
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from security import sanitize_target, sanitize_options, extract_hostname
from runner import run_streaming

app = FastAPI(title="Nikto API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

TIMEOUT_STEALTH = 2700
TIMEOUT_NORMAL  = 1800

BROWSER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/124.0.0.0",
]


class ScanRequest(BaseModel):
    target: str
    options: str = ""
    stealth: bool = True


def detect_port(target: str) -> str:
    parsed = urllib.parse.urlparse(target if "://" in target else f"http://{target}")
    if parsed.port:
        return str(parsed.port)
    return "443" if parsed.scheme == "https" else "80"


@app.get("/health")
def health():
    nikto_path = shutil.which("nikto")
    return {
        "status": "ok",
        "tool": "nikto",
        "installed": nikto_path is not None,
        "path": nikto_path,
    }


@app.post("/scan")
def run_nikto(req: ScanRequest):
    try:
        target  = sanitize_target(req.target)
        options = sanitize_options(req.options) if req.options.strip() else ""
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    nikto_path = shutil.which("nikto")
    if not nikto_path:
        raise HTTPException(
            status_code=500,
            detail="nikto is not installed. Install it with: sudo apt install nikto",
        )

    host   = extract_hostname(target)
    scheme = "https" if "https://" in target else "http"
    port   = detect_port(target)
    agent  = random.choice(BROWSER_AGENTS)

    cmd = [
        nikto_path,
        "-h", host,
        "-p", port,
        "-Format", "txt",
        "-Display", "1234EP",
        "-followredirects",
        "-useragent", agent,
    ]

    if scheme == "https":
        cmd.append("-ssl")

    if req.stealth:
        timeout = TIMEOUT_STEALTH
        cmd += [
            "-Tuning", "123457890abcx",
            "-Cgidirs", "all",
            "-maxtime", "2400s",
            "-evasion", "1",
        ]
    else:
        timeout = TIMEOUT_NORMAL
        cmd += [
            "-Tuning", "123456789abcx",
            "-Cgidirs", "all",
            "-maxtime", "1500s",
        ]

    if options:
        cmd.extend(o for o in options.split() if len(o) < 40)

    try:
        output, rc = run_streaming(cmd, timeout=timeout, label="NIKTO")
        if not output.strip():
            output = "No output returned from Nikto."
    except Exception as e:
        output = f"Error running nikto: {type(e).__name__}: {str(e)}"

    mode_label = "STEALTH" if req.stealth else "NORMAL"
    return {
        "tool": "nikto",
        "target": target,
        "mode": mode_label,
        "command": " ".join(cmd[:6]) + " ...",
        "output": output,
        "status": "completed",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
