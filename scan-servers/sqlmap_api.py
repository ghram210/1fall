import os
import shutil
import socket
import tempfile
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
    "--delay", "--flush-session", "--fresh-queries",
    "--output-dir", "-v", "--keep-alive", "--random-agent",
}


class ScanRequest(BaseModel):
    target: str
    options: str = ""
    stealth: bool = True


def _base_flag(opt: str) -> str:
    return opt.split("=")[0]


def _check_reachability(url: str) -> tuple[bool, str]:
    """Open a quick TCP connection to host:port. Returns (ok, message)."""
    try:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname
        if not host:
            return False, f"Could not parse host from URL: {url}"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror as e:
            return False, f"DNS lookup failed for '{host}': {e}"
        with socket.create_connection((ip, port), timeout=8) as _s:
            return True, f"TCP {host}:{port} ({ip}) reachable"
    except (socket.timeout, TimeoutError):
        return False, (
            f"TCP connection to {host}:{port} timed out after 8s. "
            "The target is unreachable from this machine — check your "
            "network/firewall/VPN. SQLmap cannot inject anything if it "
            "cannot connect."
        )
    except OSError as e:
        return False, f"TCP connection to {host}:{port} failed: {e}"


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

    # Pre-flight reachability check. If the target is not reachable from
    # this machine, sqlmap will burn ~90s timing out without testing
    # anything. Bail early with a clear, actionable message.
    ok, reach_msg = _check_reachability(url)
    if not ok and url.startswith("https://"):
        # Try plain HTTP fallback for sites like testphp.vulnweb.com that
        # only serve HTTP.
        http_url = "http://" + url[len("https://"):]
        ok2, reach_msg2 = _check_reachability(http_url)
        if ok2:
            url = http_url
            parsed = urllib.parse.urlparse(url)
            has_query = bool(parsed.query) and "=" in parsed.query
            reach_msg = f"{reach_msg}\n[gateway] Falling back to HTTP: {reach_msg2}"
            ok = True
    if not ok:
        return {
            "tool": "sqlmap",
            "target": target,
            "command": "",
            "output": (
                f"[PRE-FLIGHT FAILED] {reach_msg}\n\n"
                f"sqlmap was NOT executed because the target is unreachable.\n"
                f"From your machine, run:\n"
                f"    curl -v --max-time 10 {url}\n"
                f"    ping -c 3 {parsed.hostname}\n"
                f"If those also fail, the issue is your network (firewall, "
                f"VPN, ISP block, or the target is down). Pick a target you "
                f"can actually reach, then retry."
            ),
            "status": "completed",
        }

    # Use a unique output dir per scan so sqlmap never reuses cached
    # session/queries from a previous run (the main reason scans were
    # ending instantly with no findings).
    scan_output_dir = tempfile.mkdtemp(prefix="sqlmap_")

    # Belt-and-suspenders: also wipe the default per-host cache directory
    # in case sqlmap (or a user-supplied flag) ignores --output-dir.
    host = parsed.hostname or ""
    if host:
        default_cache = os.path.expanduser(
            f"~/.local/share/sqlmap/output/{host}"
        )
        try:
            shutil.rmtree(default_cache, ignore_errors=True)
        except Exception:
            pass

    # Proven, classic sqlmap config (matches official docs examples).
    # Crucially we DO NOT use --smart or --text-only here: both can cause
    # sqlmap to skip injectable parameters whose heuristic check is weak,
    # which is exactly what was killing detection.
    common = [
        sqlmap_path,
        "-u", url,
        "--batch",
        "--random-agent",
        "--flush-session",
        "--output-dir", scan_output_dir,
        "-v", "2",
        "--keep-alive",
        "--timeout=30",
        "--retries=2",
        # Max coverage: every payload, every DBMS, every technique
        # (Boolean, Error, Union, Stacked, Time, inline Query).
        "--level=5",
        "--risk=3",
    ]

    if req.stealth:
        cmd = common + ["--threads=2"]
    else:
        cmd = common + ["--threads=10"]

    if has_query:
        # URL has a parameter → enumerate databases (also implicitly
        # detects injection on every parameter).
        cmd.append("--dbs")
    else:
        # No parameter in the URL → look at HTML forms.
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

    # If the scan failed because of SSL/TLS issues on an HTTPS target,
    # automatically retry over plain HTTP. Many vulnerable test sites
    # (e.g. testphp.vulnweb.com) only serve HTTP, and sqlmap will burn
    # ~2 minutes timing out on every TLS protocol version before quitting.
    ssl_failed = (
        url.startswith("https://")
        and (
            "can't establish SSL connection" in output
            or "SSL connection error" in output
        )
    )
    if ssl_failed:
        http_url = "http://" + url[len("https://") :]
        retry_cmd = [http_url if c == url else c for c in cmd]
        retry_note = (
            f"\n\n[gateway] HTTPS connection to {url} failed (SSL timeout). "
            f"Retrying over HTTP: {http_url}\n"
        )
        try:
            retry_output, rc = run_streaming(
                retry_cmd, timeout=timeout, label="SQLMAP-HTTP"
            )
            output = output + retry_note + retry_output
            url = http_url
            cmd = retry_cmd
        except Exception as e:
            output = (
                output
                + retry_note
                + f"Error running sqlmap retry: {type(e).__name__}: {str(e)}"
            )

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
