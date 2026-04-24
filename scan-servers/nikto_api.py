import subprocess
import shutil
import urllib.parse
import random
import re
from collections import defaultdict
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

TIMEOUT_STEALTH = 1500
TIMEOUT_NORMAL  = 900

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


# ---------------------------------------------------------------------------
# Noise filtering for raw nikto output (NO severity classification)
# ---------------------------------------------------------------------------

# Lines that are pure target metadata (not findings).
META_PREFIXES = (
    "+ Target IP:", "+ Target Hostname:", "+ Target Port:", "+ Start Time:",
    "+ End Time:", "+ Site Link", "+ Root page",
    "+ No CGI Directories", "+ Hostname '",
)

# Pure noise lines that aren't findings at all (cookie echoes, version notice).
NOISE_PATTERNS = (
    re.compile(r"sent cookie:\s*JSESSIONID", re.IGNORECASE),
    re.compile(r"sent cookie:\s*PHPSESSID",  re.IGNORECASE),
    re.compile(r"sent cookie:\s*ASP\.NET_SessionId", re.IGNORECASE),
    re.compile(r"installation is out of date", re.IGNORECASE),
)


def _normalize_for_dedup(text: str) -> str:
    """Collapse variable bits (paths, ids, numbers) so repeated findings
    across many endpoints become a single fingerprint."""
    s = text
    s = re.sub(r"OSVDB-\d+:?\s*", "", s)
    s = re.sub(r"/[A-Za-z0-9_\-./%]+", "/<path>", s)
    s = re.sub(r"\b[0-9a-fA-F]{16,}\b", "<hash>", s)
    s = re.sub(r"\b\d+\b", "<num>", s)
    s = re.sub(r"\s+", " ", s).strip().lower()
    return s


def parse_nikto_output(raw: str) -> tuple[list[dict], list[str]]:
    """Returns (deduped_findings, metadata_lines). No severity assigned."""
    if not raw or not raw.strip():
        return [], []

    metadata: list[str] = []
    grouped: dict[str, dict] = defaultdict(lambda: {"text": "", "count": 0, "paths": []})

    for line in raw.splitlines():
        line = line.rstrip()
        if not line:
            continue

        if any(line.startswith(p) for p in META_PREFIXES):
            metadata.append(line)
            continue

        if not line.lstrip().startswith("+"):
            continue

        text = line.lstrip("+ ").strip()

        if any(p.search(text) for p in NOISE_PATTERNS):
            continue

        norm = _normalize_for_dedup(text)
        path_match = re.search(r"(/[A-Za-z0-9_\-./%]+)", text)
        path = path_match.group(1) if path_match else ""

        entry = grouped[norm]
        entry["text"]   = entry["text"] or text
        entry["count"] += 1
        if path and path not in entry["paths"] and len(entry["paths"]) < 3:
            entry["paths"].append(path)

    findings = sorted(grouped.values(), key=lambda f: -f["count"])
    return findings, metadata


def format_nikto(raw: str, target: str, mode: str) -> str:
    findings, metadata = parse_nikto_output(raw)

    if not findings and not metadata:
        return f"NIKTO [{mode} MODE]: No output for {target}."

    raw_count = sum(1 for l in raw.splitlines() if l.lstrip().startswith("+"))
    kept      = sum(f["count"] for f in findings)

    lines = [
        f"NIKTO [{mode} MODE] — Target: {target}",
        f"Unique findings: {len(findings)}  "
        f"(deduplicated from {kept} hits, filtered {raw_count - kept - len(metadata)} noise lines)",
        "=" * 60,
    ]

    if metadata:
        lines.append("")
        lines.append("Target metadata:")
        for m in metadata[:10]:
            lines.append(f"  {m}")
        lines.append("=" * 60)

    if findings:
        lines.append("")
        lines.append(f"Findings ({len(findings)} unique):")
        lines.append("-" * 40)
        for f in findings:
            head = f"  {f['text']}"
            if f["count"] > 1:
                head += f"  (seen {f['count']}×)"
            lines.append(head)
            if f["paths"]:
                lines.append(f"      paths: {', '.join(f['paths'])}")

    return "\n".join(lines)


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

    # Tuning legend: 1=Files, 2=Misconfig, 3=Info Disclosure, 4=Injection,
    # 5=Remote File Retrieval, 7=RCE, 8=Cmd Exec, 9=SQLi, b=Auth, x=Reverse
    # We drop 0,a,c (denial-of-service / auth-bypass spam / brute) for speed.
    # We DO NOT use -evasion: random URI encoding makes every request unique
    # which generates a fresh JSESSIONID per hit and floods output with noise.
    if req.stealth:
        timeout = TIMEOUT_STEALTH
        cmd += [
            "-Tuning", "1234579bx",
            "-maxtime", "1200s",
        ]
    else:
        timeout = TIMEOUT_NORMAL
        cmd += [
            "-Tuning", "1234579bx",
            "-maxtime", "600s",
        ]

    if options:
        cmd.extend(o for o in options.split() if len(o) < 40)

    mode_label = "STEALTH" if req.stealth else "NORMAL"
    try:
        raw, rc = run_streaming(cmd, timeout=timeout, label="NIKTO")
        if not raw.strip():
            output = f"NIKTO [{mode_label} MODE]: No output returned from Nikto."
        else:
            output = format_nikto(raw, target, mode_label)
    except Exception as e:
        output = f"Error running nikto: {type(e).__name__}: {str(e)}"
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
