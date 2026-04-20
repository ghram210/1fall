import subprocess
import shutil
import urllib.parse
import random
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from security import sanitize_target, sanitize_options, extract_hostname

app = FastAPI(title="Nikto API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Stealth mode timeout: 45 min | Normal mode timeout: 30 min
TIMEOUT_STEALTH = 2700
TIMEOUT_NORMAL  = 1800

# Realistic browser User-Agents for stealth
BROWSER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/124.0.0.0",
]


class ScanRequest(BaseModel):
    target: str
    options: str = ""
    stealth: bool = True   # default: stealth ON


def detect_port(target: str) -> str:
    parsed = urllib.parse.urlparse(target if "://" in target else f"http://{target}")
    if parsed.port:
        return str(parsed.port)
    return "443" if parsed.scheme == "https" else "80"


@app.get("/health")
def health():
    return {"status": "ok", "tool": "nikto"}


@app.post("/scan")
def run_nikto(req: ScanRequest):
    try:
        target  = sanitize_target(req.target)
        options = sanitize_options(req.options)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    nikto_path = shutil.which("nikto")
    if not nikto_path:
        raise HTTPException(
            status_code=500,
            detail="Tool nikto is not installed on the system",
        )

    host   = extract_hostname(target)
    scheme = "https" if "https://" in target else "http"
    port   = detect_port(target)
    agent  = random.choice(BROWSER_AGENTS)

    # -------------------------------------------------------
    # Base command — common to both modes
    # -------------------------------------------------------
    cmd = [
        nikto_path,
        "-h", f"{scheme}://{host}",
        "-p", port,
        "-Format", "txt",
        "-Display", "1234EP",
        "-nolookup",
        "-followredirects",
        "-useragent", agent,
    ]

    if scheme == "https":
        cmd.append("-ssl")

    # -------------------------------------------------------
    # STEALTH MODE — solves: noise, alerts, IP ban
    # -------------------------------------------------------
    if req.stealth:
        timeout = TIMEOUT_STEALTH
        cmd += [
            # Test categories — excludes DoS (6) to avoid server damage
            "-Tuning", "0123457890abcx",

            # Cookie testing
            "-C", "all",

            # Max scan time
            "-maxtime", "2400s",

            # --- SOLUTION 1: Reduce noise ---
            # Pause N seconds between every request (reduces req/sec drastically)
            "-pause", "2",

            # --- SOLUTION 2: Evade security alerts / IDS / WAF ---
            # Nikto evasion techniques:
            # 1 = Random URL encoding of non-alphanumeric chars
            # 2 = Directory self-reference (/./admin instead of /admin)
            # 3 = Premature URL ending (adds null byte tricks)
            # 4 = Prepend long random string to confuse pattern matching
            # 5 = Fake URL parameter (/admin?fake=randomvalue)
            # 6 = TAB as request spacer instead of space
            # 7 = Random case in URL (/AdMiN instead of /admin)
            # 8 = Windows-style path separator (\admin instead of /admin)
            "-evasion", "1234567",
        ]

    # -------------------------------------------------------
    # NORMAL MODE — full speed, all categories
    # -------------------------------------------------------
    else:
        timeout = TIMEOUT_NORMAL
        cmd += [
            "-Tuning", "0123456789abcx",
            "-C", "all",
            "-maxtime", "1500s",
        ]

    # Extra user-supplied options
    if options:
        cmd.extend(o for o in options.split() if len(o) < 40)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = result.stdout or ""
        if result.stderr:
            output += "\n[STDERR]\n" + result.stderr
        if not output.strip():
            output = "No output returned from Nikto."
    except subprocess.TimeoutExpired:
        output = f"Nikto scan timed out after {timeout // 60} minutes."
    except Exception as e:
        output = f"Error running nikto: {str(e)}"

    mode_label = "STEALTH" if req.stealth else "NORMAL"
    return {
        "tool": "nikto",
        "target": target,
        "mode": mode_label,
        "output": output,
        "status": "completed",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
