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


def _probe(test_url: str, agent: str, timeout: int = 8):
    """Single HTTP probe → (status, size, words, lines) or None on failure."""
    try:
        req = urllib.request.Request(
            test_url,
            headers={
                "User-Agent": agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
        )
        # Disable SSL verification for self-signed / lab targets.
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read()
            text = body.decode("utf-8", errors="ignore")
            return (
                resp.status,
                len(body),
                len(text.split()),
                len(text.splitlines()),
            )
    except Exception:
        return None


def resolve_reachable_base(base_url: str, agent: str) -> str:
    """
    Make sure the base URL is actually reachable. If http:// fails, try https://.
    Returns the working base URL (with trailing slash) or the original if neither works.
    """
    if _probe(base_url, agent, timeout=8) is not None:
        return base_url

    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme == "http":
        alt = urllib.parse.urlunparse(("https",) + parsed[1:])
        if _probe(alt, agent, timeout=8) is not None:
            print(f"[FFUF-RESOLVE] http:// unreachable → falling back to https://", flush=True)
            return alt
    elif parsed.scheme == "https":
        alt = urllib.parse.urlunparse(("http",) + parsed[1:])
        if _probe(alt, agent, timeout=8) is not None:
            print(f"[FFUF-RESOLVE] https:// unreachable → falling back to http://", flush=True)
            return alt

    return base_url


def calibrate_baseline(base_url: str, agent: str) -> list[str]:
    """
    Probe several random non-existent paths to fingerprint the site's default
    "not-found" response. Filter on size + words + lines so SPA shells (where
    every unknown URL returns the same index.html) can still be filtered out
    accurately, while real content (API endpoints, static files of different
    sizes) still surfaces.
    """
    filter_args: list[str] = []
    samples: list[tuple[int, int, int, int]] = []  # (status, size, words, lines)

    for _ in range(3):
        rand_path = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
        result = _probe(f"{base_url}{rand_path}", agent)
        if result is not None:
            samples.append(result)

    if not samples:
        # Couldn't reach the target at all — fall back to ffuf's built-in
        # auto-calibration (it will probe on its own once running).
        print("[FFUF-CALIBRATE] Could not reach target — using ffuf auto-calibration", flush=True)
        filter_args += ["-ac", "-acc", "/", "-acc", "index", "-acc", "404page"]
        return filter_args

    statuses = sorted({s[0] for s in samples})
    sizes    = sorted({s[1] for s in samples})
    words    = sorted({s[2] for s in samples})
    lines    = sorted({s[3] for s in samples})

    print(f"[FFUF-CALIBRATE] Baseline statuses={statuses} sizes={sizes} words={words} lines={lines}", flush=True)

    # Soft-404 detection: server returns 200 for unknown paths (typical SPAs,
    # frameworks like React/Angular/Vue, or misconfigured catch-alls).
    if 200 in statuses:
        print("[FFUF-CALIBRATE] Soft-404 / SPA detected — filtering by size+words+lines", flush=True)

    # Multi-dimensional filter: a real find has to differ in at least one
    # of (size, words, lines) from EVERY baseline sample.
    if sizes:
        filter_args += ["-fs", ",".join(str(s) for s in sizes)]
    if words and len(words) <= 5:
        filter_args += ["-fw", ",".join(str(w) for w in words)]
    if lines and len(lines) <= 5:
        filter_args += ["-fl", ",".join(str(l) for l in lines)]

    return filter_args


def deduplicate_noise(results: list, threshold: int = 6) -> tuple[list, list]:
    """
    Remove "noise clusters": groups of findings sharing the same response
    fingerprint (status + size + words + lines). When more than `threshold`
    paths return identical responses, it is virtually always a blanket
    WAF/Cloudflare page or a generic server-error template, not real content.

    Returns (real_findings, dropped_clusters_summary).
    """
    from collections import defaultdict
    clusters: dict[tuple, list] = defaultdict(list)
    for r in results:
        key = (
            r.get("status", 0),
            r.get("length", 0),
            r.get("words", 0),
            r.get("lines", 0),
        )
        clusters[key].append(r)

    real: list = []
    dropped: list = []
    for key, items in clusters.items():
        if len(items) >= threshold:
            dropped.append({
                "status": key[0], "size": key[1], "words": key[2], "lines": key[3],
                "count":  len(items),
                "sample": items[0].get("input", {}).get("FUZZ", ""),
            })
        else:
            real.extend(items)
    return real, dropped


def format_results(data: dict, target: str, mode: str) -> str:
    raw_results = data.get("results", [])
    if not raw_results:
        return f"FFUF [{mode} MODE]: No accessible paths found for {target}."

    results, dropped = deduplicate_noise(raw_results)

    findings: list[dict] = []
    for r in results:
        findings.append({
            "path":     r.get("input", {}).get("FUZZ", ""),
            "status":   r.get("status", 0),
            "size":     r.get("length", 0),
            "words":    r.get("words", 0),
            "redirect": r.get("redirectlocation", ""),
        })

    lines = [
        f"FFUF [{mode} MODE] — Target: {target}",
        f"Real findings: {len(results)}  (filtered out {len(raw_results) - len(results)} noise hits)",
        "=" * 60,
    ]

    if dropped:
        lines.append("")
        lines.append("Filtered noise clusters (likely WAF/Cloudflare/error templates — NOT vulnerabilities):")
        for d in sorted(dropped, key=lambda x: -x["count"]):
            lines.append(
                f"  - {d['count']} paths returned identical "
                f"HTTP {d['status']} (size={d['size']}, words={d['words']}, lines={d['lines']}) "
                f"e.g. /{d['sample']}"
            )
        lines.append("=" * 60)

    if findings:
        lines.append(f"\nFindings ({len(findings)}):")
        lines.append("-" * 40)
        for r in findings:
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

    # Auto-fallback http <-> https if the original scheme isn't reachable.
    url = resolve_reachable_base(url, agent)

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
