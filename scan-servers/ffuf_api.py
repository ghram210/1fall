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
from runner import run_streaming

app = FastAPI(title="FFUF API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

TIMEOUT_STEALTH = 3600
TIMEOUT_NORMAL  = 2400

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

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]

FALLBACK_WORDS = [
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


class ScanRequest(BaseModel):
    target: str
    options: str = ""
    stealth: bool = True


def get_best_wordlist() -> str:
    for wl in WORDLISTS:
        if os.path.exists(wl) and os.path.getsize(wl) > 0:
            return wl
    if not os.path.exists(FALLBACK_WORDLIST) or os.path.getsize(FALLBACK_WORDLIST) == 0:
        with open(FALLBACK_WORDLIST, "w") as f:
            f.write("\n".join(FALLBACK_WORDS))
    return FALLBACK_WORDLIST


def format_results(data: dict, target: str, mode: str) -> str:
    results = data.get("results", [])
    if not results:
        return f"FFUF [{mode} MODE]: No results found for {target}."

    by_status: dict[int, list] = {}
    for r in results:
        code = r.get("status", 0)
        by_status.setdefault(code, []).append(r)

    status_labels = {
        200: "OK 200",
        201: "Created 201",
        204: "No Content 204",
        301: "Redirect 301",
        302: "Found 302",
        307: "Temp Redirect 307",
        400: "Bad Request 400",
        401: "Unauthorized 401",
        403: "Forbidden 403",
        405: "Method Not Allowed 405",
        500: "Server Error 500",
        503: "Unavailable 503",
    }

    lines = [
        f"FFUF [{mode} MODE] — Target: {target}",
        f"Total findings: {len(results)}",
        "=" * 60,
    ]

    for code in sorted(by_status.keys()):
        label = status_labels.get(code, str(code))
        lines.append(f"\n[{label}] ({len(by_status[code])} found):")
        lines.append("-" * 40)
        for r in by_status[code]:
            path     = r.get("input", {}).get("FUZZ", "")
            size     = r.get("length", 0)
            words    = r.get("words", 0)
            redirect = r.get("redirectlocation", "")
            line = f"  /{path}  [Size:{size} Words:{words}]"
            if redirect:
                line += f"  -> {redirect}"
            lines.append(line)

    return "\n".join(lines)


@app.get("/health")
def health():
    ffuf_path = shutil.which("ffuf")
    wordlist = get_best_wordlist()
    return {
        "status": "ok",
        "tool": "ffuf",
        "installed": ffuf_path is not None,
        "path": ffuf_path,
        "wordlist": wordlist,
    }


@app.post("/scan")
def run_ffuf(req: ScanRequest):
    try:
        target  = sanitize_target(req.target)
        options = sanitize_options(req.options) if req.options.strip() else ""
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    ffuf_path = shutil.which("ffuf")
    if not ffuf_path:
        raise HTTPException(
            status_code=500,
            detail="ffuf is not installed. Install it with: sudo apt install ffuf",
        )

    wordlist = get_best_wordlist()
    url = target if "://" in target else f"http://{target}"
    if not url.endswith("/"):
        url += "/"

    agent = random.choice(USER_AGENTS)

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out_file = tmp.name

    cmd = [
        ffuf_path,
        "-u", f"{url}FUZZ",
        "-w", f"{wordlist}:FUZZ",
        "-e", EXTENSIONS,
        "-mc", "200,201,204,301,302,307,308,401,403,405,500,503",
        "-fc", "404",
        "-ic",
        "-r",
        "-o", out_file,
        "-of", "json",
        "-H", f"User-Agent: {agent}",
        "-H", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "-H", "Accept-Language: en-US,en;q=0.9",
        "-H", "Connection: keep-alive",
    ]

    if req.stealth:
        timeout = TIMEOUT_STEALTH
        mode    = "STEALTH"
        cmd += [
            "-t", "10",
            "-rate", "30",
            "-p", "0.5-1.5",
            "-timeout", "15",
        ]
    else:
        timeout = TIMEOUT_NORMAL
        mode    = "NORMAL"
        cmd += [
            "-t", "40",
            "-rate", "150",
            "-timeout", "10",
        ]

    if options:
        cmd.extend(o for o in options.split() if len(o) < 40)

    output = ""
    raw_stream = ""
    try:
        raw_stream, rc = run_streaming(cmd, timeout=timeout, label="FFUF")

        if os.path.exists(out_file) and os.path.getsize(out_file) > 0:
            with open(out_file) as f:
                data = json.load(f)
            output = format_results(data, target, mode)
        else:
            if raw_stream.strip():
                output = f"FFUF [{mode}]:\n{raw_stream}"
            else:
                output = f"FFUF [{mode} MODE]: No accessible paths found on {target}."

    except json.JSONDecodeError:
        output = f"FFUF returned invalid JSON.\nRaw:\n{raw_stream}"
    except Exception as e:
        output = f"Error running ffuf: {type(e).__name__}: {str(e)}"
    finally:
        if os.path.exists(out_file):
            os.unlink(out_file)

    return {
        "tool": "ffuf",
        "target": target,
        "mode": mode,
        "wordlist": wordlist,
        "output": output,
        "status": "completed",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8004)
