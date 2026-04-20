import subprocess
import shutil
import json
import tempfile
import os
import random
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from security import sanitize_target, sanitize_options

app = FastAPI(title="FFUF API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Timeouts
TIMEOUT_STEALTH = 3600   # 60 min (slower rate = needs more time)
TIMEOUT_NORMAL  = 2400   # 40 min

# Wordlist priority (largest → smallest)
WORDLISTS = [
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
]

EXTENSIONS = ".php,.html,.htm,.asp,.aspx,.js,.json,.xml,.txt,.bak,.old,.conf,.config,.env,.log,.zip,.sql,.db"

FALLBACK_WORDLIST = os.path.join(os.path.dirname(__file__), "wordlist_full.txt")

# Realistic browser User-Agents pool for rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]


class ScanRequest(BaseModel):
    target: str
    options: str = ""
    stealth: bool = True   # default: stealth ON


def get_best_wordlist() -> str:
    for wl in WORDLISTS:
        if os.path.exists(wl) and os.path.getsize(wl) > 0:
            return wl
    if not os.path.exists(FALLBACK_WORDLIST):
        words = [
            "admin", "administrator", "login", "dashboard", "panel", "cpanel",
            "api", "api/v1", "api/v2", "v1", "v2", "graphql", "rest",
            "config", "configuration", "settings", "setup", "install",
            "backup", "backups", "bak", "old", "temp", "tmp", "cache",
            "test", "testing", "dev", "development", "staging", "prod",
            "debug", "trace", "logs", "log",
            "upload", "uploads", "file", "files", "media", "images",
            "static", "assets", "css", "js", "fonts", "img",
            "wp-admin", "wp-login.php", "wp-content", "wp-includes",
            "phpmyadmin", "pma", "myadmin", "mysql", "adminer",
            "xmlrpc.php", "readme.html", "license.txt",
            ".git", ".env", ".htaccess", ".htpasswd", ".DS_Store",
            "web.config", "crossdomain.xml", "sitemap.xml", "robots.txt",
            "server-status", "server-info",
            "console", "shell", "cmd", "exec",
            "user", "users", "account", "accounts", "profile",
            "register", "signup", "logout", "auth", "oauth",
            "forgot", "reset", "password", "passwd",
            "search", "query", "feed", "rss", "ajax",
            "data", "database", "export", "import", "download",
            "cgi-bin", "scripts", "bin", "include", "includes",
            "lib", "library", "vendor", "node_modules",
            "swagger", "swagger-ui", "openapi", "docs", "documentation",
            "healthz", "health", "status", "ping", "metrics", "monitor",
            "admin.php", "admin.html", "index.php", "index.html",
            "login.php", "login.html", "signin.php",
            "register.php", "signup.php",
            "config.php", "config.yml", "config.json", "settings.php",
            "database.php", "db.php", "connection.php",
            "upload.php", "uploader.php", "filemanager",
            "info.php", "phpinfo.php", "test.php",
            "error_log", "error.log", "access.log", "debug.log",
        ]
        with open(FALLBACK_WORDLIST, "w") as f:
            f.write("\n".join(words))
    return FALLBACK_WORDLIST


def format_results(data: dict, target: str, mode: str) -> str:
    results = data.get("results", [])
    if not results:
        return f"FFUF [{mode} MODE]: No results found."

    by_status: dict[int, list] = {}
    for r in results:
        code = r.get("status", 0)
        by_status.setdefault(code, []).append(r)

    status_labels = {
        200: "✅ 200 OK",
        201: "✅ 201 Created",
        204: "✅ 204 No Content",
        301: "↪  301 Moved Permanently",
        302: "↪  302 Found (Redirect)",
        307: "↪  307 Temporary Redirect",
        400: "⚠️  400 Bad Request",
        401: "🔒 401 Unauthorized",
        403: "🔒 403 Forbidden",
        405: "⚠️  405 Method Not Allowed",
        500: "💥 500 Internal Server Error",
        503: "💥 503 Service Unavailable",
    }

    lines = [
        f"FFUF [{mode} MODE] — Target: {target}",
        f"Total findings: {len(results)}",
        "=" * 60,
    ]

    for code in sorted(by_status.keys()):
        label = status_labels.get(code, f"   {code}")
        lines.append(f"\n{label} ({len(by_status[code])} found):")
        lines.append("-" * 40)
        for r in by_status[code]:
            path     = r.get("input", {}).get("FUZZ", "")
            size     = r.get("length", 0)
            words    = r.get("words", 0)
            redirect = r.get("redirectlocation", "")
            line = f"  /{path}  [Size:{size} Words:{words}]"
            if redirect:
                line += f"  → {redirect}"
            lines.append(line)

    return "\n".join(lines)


@app.get("/health")
def health():
    return {"status": "ok", "tool": "ffuf"}


@app.post("/scan")
def run_ffuf(req: ScanRequest):
    try:
        target  = sanitize_target(req.target)
        options = sanitize_options(req.options)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    ffuf_path = shutil.which("ffuf")
    if not ffuf_path:
        raise HTTPException(
            status_code=500,
            detail="Tool ffuf is not installed on the system",
        )

    wordlist = get_best_wordlist()
    url = target if "://" in target else f"http://{target}"
    if not url.endswith("/"):
        url += "/"

    agent = random.choice(USER_AGENTS)

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out_file = tmp.name

    # -------------------------------------------------------
    # Base command — common to both modes
    # -------------------------------------------------------
    cmd = [
        ffuf_path,
        "-u", f"{url}FUZZ",
        "-w", f"{wordlist}:FUZZ",
        "-e", EXTENSIONS,
        "-mc", "200,201,204,301,302,307,401,403,405,500,503",
        "-ic",
        "-ac",
        "-r",
        "-o", out_file,
        "-of", "json",
        "-s",

        # --- SOLUTION 2: Mimic real browser (evades WAF/IDS fingerprinting) ---
        "-H", f"User-Agent: {agent}",
        "-H", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "-H", "Accept-Language: en-US,en;q=0.9",
        "-H", "Accept-Encoding: gzip, deflate",
        "-H", "Connection: keep-alive",
        "-H", "Upgrade-Insecure-Requests: 1",
    ]

    # -------------------------------------------------------
    # STEALTH MODE
    # -------------------------------------------------------
    if req.stealth:
        timeout = TIMEOUT_STEALTH
        mode    = "STEALTH"
        cmd += [
            # --- SOLUTION 1: Reduce noise (fewer threads = fewer parallel requests) ---
            "-t", "5",

            # --- SOLUTION 3: Prevent IP ban (rate limit + random delay) ---
            # Max 15 requests per second
            "-rate", "15",
            # Random delay 1.0–3.0 seconds between each request
            "-p", "1.0-3.0",

            # No recursion in stealth (massively reduces total requests)
            # Recursion depth 1 if a dir is found
            "-recursion",
            "-recursion-depth", "1",

            # Per-request timeout
            "-timeout", "15",
        ]

    # -------------------------------------------------------
    # NORMAL MODE — full speed
    # -------------------------------------------------------
    else:
        timeout = TIMEOUT_NORMAL
        mode    = "NORMAL"
        cmd += [
            "-t", "50",
            "-rate", "100",
            "-recursion",
            "-recursion-depth", "3",
            "-timeout", "10",
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

        if os.path.exists(out_file) and os.path.getsize(out_file) > 0:
            with open(out_file) as f:
                data = json.load(f)
            output = format_results(data, target, mode)
        else:
            raw = result.stdout or result.stderr or "No results found."
            output = f"FFUF [{mode}]:\n{raw}"

    except subprocess.TimeoutExpired:
        output = f"FFUF [{mode}] timed out after {timeout // 60} minutes."
    except json.JSONDecodeError:
        output = f"FFUF returned invalid JSON.\nRaw:\n{getattr(result, 'stdout', '')}"
    except Exception as e:
        output = f"Error running ffuf: {str(e)}"
    finally:
        if os.path.exists(out_file):
            os.unlink(out_file)

    return {
        "tool": "ffuf",
        "target": target,
        "mode": mode,
        "output": output,
        "status": "completed",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8004)