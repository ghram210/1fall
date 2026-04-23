import shutil
import json
import tempfile
import os
import random
import string
import urllib.parse
import urllib.request
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

TIMEOUT_STEALTH = 2400
TIMEOUT_NORMAL  = 1200

WORDLISTS = [
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
    "/usr/share/seclists/Discovery/Web-Content/big.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    "/usr/share/wordlists/dirb/big.txt",
    "/usr/share/wordlists/dirb/common.txt",
]

EXTENSIONS = ".php,.html,.htm,.asp,.aspx,.js,.json,.xml,.txt,.bak,.old,.conf,.config,.env,.log,.zip,.sql,.db"

FALLBACK_WORDLIST = os.path.join(os.path.dirname(__file__), "wordlist_full.txt")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
]

FALLBACK_WORDS = [
    "admin", "administrator", "login", "dashboard", "panel", "cpanel", "manage", "manager",
    "api", "api/v1", "api/v2", "api/v3", "v1", "v2", "graphql", "rest", "rpc",
    "config", "configuration", "settings", "setup", "install", "installer",
    "backup", "backups", "bak", "old", "temp", "tmp", "cache", "archive",
    "test", "testing", "dev", "development", "staging", "prod", "production", "demo",
    "debug", "trace", "logs", "log", "error", "errors",
    "upload", "uploads", "file", "files", "media", "images", "img", "image",
    "static", "assets", "css", "js", "fonts", "resources",
    "wp-admin", "wp-login.php", "wp-content", "wp-includes", "wordpress",
    "phpmyadmin", "pma", "myadmin", "mysql", "adminer", "dbadmin",
    "xmlrpc.php", "readme.html", "readme.txt", "license.txt", "changelog.txt",
    ".git", ".env", ".htaccess", ".htpasswd", ".DS_Store", ".svn",
    "web.config", "crossdomain.xml", "sitemap.xml", "robots.txt",
    "server-status", "server-info", "nginx_status", "info.php", "phpinfo.php",
    "console", "shell", "cmd", "exec", "terminal", "webshell",
    "user", "users", "account", "accounts", "profile", "profiles",
    "register", "signup", "logout", "auth", "oauth", "sso", "saml",
    "forgot", "reset", "password", "passwd", "credentials",
    "search", "query", "feed", "rss", "ajax", "xhr",
    "data", "database", "export", "import", "download", "report", "reports",
    "cgi-bin", "scripts", "bin", "include", "includes", "lib", "vendor",
    "swagger", "swagger-ui", "openapi", "docs", "documentation", "apidoc",
    "healthz", "health", "status", "ping", "metrics", "monitor", "actuator",
    "admin.php", "admin.html", "index.php", "index.html", "index.asp",
    "login.php", "login.html", "login.asp", "signin.php", "signin.html",
    "register.php", "signup.php", "logout.php",
    "config.php", "config.yml", "config.json", "settings.php", "app.config",
    "database.php", "db.php", "connection.php", "connect.php",
    "upload.php", "uploader.php", "filemanager", "fileupload",
    "info.php", "phpinfo.php", "test.php", "check.php",
    "error_log", "error.log", "access.log", "debug.log", "app.log",
    "app", "application", "portal", "intranet", "extranet",
    "private", "hidden", "secret", "secure", "internal", "restricted",
    "finance", "hr", "legal", "sales", "marketing", "engineering",
    "forum", "blog", "cms", "shop", "store", "cart", "checkout",
    "payment", "invoice", "billing", "subscription",
    "ticket", "tickets", "helpdesk", "support", "feedback",
    "mail", "email", "smtp", "webmail", "newsletter",
    "home", "welcome", "main", "index", "default",
    "about", "contact", "faq", "help", "terms", "privacy",
    "token", "tokens", "key", "keys", "api-key", "secret-key",
    "certificate", "certs", "ssl", "tls",
    "old-admin", "new-admin", "backend", "frontend",
    "system", "sys", "root", "core", "base",
    "public", "private", "protected", "common",
    "ajax.php", "api.php", "callback.php", "webhook.php", "hook.php",
    "proxy.php", "redirect.php", "redir.php",
    "cron.php", "task.php", "jobs.php", "queue.php",
    "install.php", "setup.php", "update.php", "upgrade.php",
    "verify.php", "validate.php", "activate.php",
    "edit.php", "delete.php", "add.php", "remove.php", "create.php",
    "view.php", "show.php", "display.php", "list.php", "get.php",
    "send.php", "post.php", "submit.php", "process.php", "handle.php",
    "user.php", "users.php", "member.php", "members.php",
    "admin2", "admin1", "admin3", "administrator2",
    "ajax", "api2", "backup2", "logs2",
    "sql", "mysql", "sqlite", "redis", "mongodb",
    "docker", "kubernetes", "k8s", "deploy",
    "ci", "cd", "jenkins", "gitlab", "github",
    "aws", "azure", "gcp", "cloud",
]

SEVERITY_MAP = {
    "critical": [
        ".env", ".git", ".svn", "phpinfo.php", "info.php", "web.config",
        "database.php", "db.php", "connection.php", ".htpasswd",
        "config.php", "backup", "backups", ".bak", ".sql", ".db",
        "shell", "cmd", "exec", "webshell", "adminer", "phpmyadmin",
        "secret", "credentials", "token", "api-key", "secret-key",
    ],
    "high": [
        "admin", "administrator", "cpanel", "panel", "wp-admin",
        "wp-login.php", "upload.php", "uploader.php", "filemanager",
        "login.php", "signin.php", "console", "debug",
        "server-status", "server-info", "nginx_status", ".DS_Store", ".htaccess",
        "swagger", "openapi", "graphql", "actuator",
        "private", "internal", "restricted", "manage", "manager",
    ],
    "medium": [
        "api", "api/v1", "api/v2", "api/v3", "graphql", "swagger-ui",
        "dev", "development", "staging", "test", "testing", "demo",
        "config", "settings", "setup", "configuration", "install",
        "logs", "log", "error_log", "access.log", "debug.log",
        "crossdomain.xml", "xmlrpc.php", "cors", "webhook",
    ],
    "low": [
        "robots.txt", "sitemap.xml", "readme.html", "license.txt", "changelog.txt",
        "docs", "documentation", "static", "assets", "public",
    ],
}


def classify_severity(path: str, status: int) -> str:
    path_lower = path.lower()
    for severity, keywords in SEVERITY_MAP.items():
        for kw in keywords:
            if kw in path_lower:
                return severity
    if status == 500:
        return "high"
    if status in (401, 403):
        return "medium"
    if status in (301, 302, 307, 308):
        return "low"
    return "info"


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


def build_base_url(target: str) -> str:
    url = target if "://" in target else f"http://{target}"
    parsed = urllib.parse.urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path
    path = path.replace("FUZZ", "").rstrip("/")
    return f"{base}{path}/"


def calibrate_baseline(base_url: str, agent: str) -> list[str]:
    """
    Fetch a random nonexistent path to detect the site's default response size.
    Returns a list of -fs / -fw / -fl arguments to filter the baseline.
    """
    filter_args: list[str] = []
    sizes: list[int] = []

    for _ in range(2):
        rand_path = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
        test_url = f"{base_url}{rand_path}"
        try:
            req = urllib.request.Request(
                test_url,
                headers={
                    "User-Agent": agent,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                },
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                body = resp.read()
                sizes.append(len(body))
        except Exception:
            pass

    if len(sizes) >= 1:
        unique_sizes = list(set(sizes))
        filter_args += ["-fs", ",".join(str(s) for s in unique_sizes)]
        print(f"[FFUF-CALIBRATE] Baseline page size(s): {unique_sizes} — will filter these out", flush=True)
    else:
        print("[FFUF-CALIBRATE] Could not reach target for calibration, using -ac", flush=True)
        filter_args.append("-ac")

    return filter_args


def format_results(data: dict, target: str, mode: str) -> str:
    results = data.get("results", [])
    if not results:
        return f"FFUF [{mode} MODE]: No accessible paths found for {target}."

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    by_severity: dict[str, list] = {s: [] for s in counts}

    for r in results:
        path     = r.get("input", {}).get("FUZZ", "")
        status   = r.get("status", 0)
        size     = r.get("length", 0)
        words    = r.get("words", 0)
        redirect = r.get("redirectlocation", "")
        severity = classify_severity(path, status)
        counts[severity] += 1
        by_severity[severity].append({
            "path": path, "status": status,
            "size": size, "words": words, "redirect": redirect,
        })

    lines = [
        f"FFUF [{mode} MODE] — Target: {target}",
        f"Total findings: {len(results)}",
        f"Critical: {counts['critical']}  High: {counts['high']}  "
        f"Medium: {counts['medium']}  Low: {counts['low']}  Info: {counts['info']}",
        "=" * 60,
    ]

    severity_labels = {
        "critical": "[CRITICAL]",
        "high":     "[HIGH]    ",
        "medium":   "[MEDIUM]  ",
        "low":      "[LOW]     ",
        "info":     "[INFO]    ",
    }

    for severity in ("critical", "high", "medium", "low", "info"):
        items = by_severity[severity]
        if not items:
            continue
        lines.append(f"\n{severity_labels[severity]} ({len(items)} found):")
        lines.append("-" * 40)
        for r in items:
            line = f"  /{r['path']}  [HTTP {r['status']} | Size:{r['size']} Words:{r['words']}]"
            if r["redirect"]:
                line += f"  -> {r['redirect']}"
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
        "wordlist_size": os.path.getsize(wordlist) if os.path.exists(wordlist) else 0,
        "tip": "Install SecLists for best results: sudo apt install seclists",
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
    url      = build_base_url(target)
    agent    = random.choice(USER_AGENTS)

    filter_args = calibrate_baseline(url, agent)

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
        "-v",
        "-o", out_file,
        "-of", "json",
        "-H", f"User-Agent: {agent}",
        "-H", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "-H", "Accept-Language: en-US,en;q=0.9",
        "-H", "Connection: keep-alive",
    ] + filter_args

    if req.stealth:
        timeout = TIMEOUT_STEALTH
        mode    = "STEALTH"
        cmd += [
            "-t", "20",
            "-rate", "60",
            "-p", "0.1-0.3",
            "-timeout", "15",
        ]
    else:
        timeout = TIMEOUT_NORMAL
        mode    = "NORMAL"
        cmd += [
            "-t", "50",
            "-rate", "200",
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
            output = (
                f"FFUF [{mode}]:\n{raw_stream}"
                if raw_stream.strip()
                else f"FFUF [{mode} MODE]: No accessible paths found on {target}."
            )

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
