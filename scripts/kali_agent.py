#!/usr/bin/env python3
"""
Vulnerability Manager - Kali Linux Agent
=========================================
Run this on your Kali Linux machine.
It polls Supabase for pending scans, executes the tools, and uploads findings.

Requirements:
    pip3 install supabase

Tools needed on Kali:
    sudo apt install nmap nikto sqlmap ffuf -y

Usage:
    python3 kali_agent.py

Configuration:
    Edit the SUPABASE_URL and SUPABASE_SERVICE_KEY variables below,
    OR set environment variables:
        export SUPABASE_URL="https://your-project.supabase.co"
        export SUPABASE_SERVICE_KEY="your-service-role-key"
"""

import os
import sys
import json
import time
import socket
import subprocess
import re
import tempfile
import logging
from datetime import datetime, timezone
from typing import Optional

try:
    from supabase import create_client, Client
except ImportError:
    print("ERROR: supabase library not installed.")
    print("Run: pip3 install supabase")
    sys.exit(1)

# ============================================================
# CONFIGURATION — Edit these or set as environment variables
# ============================================================
SUPABASE_URL = os.getenv("SUPABASE_URL", "https://YOUR_PROJECT.supabase.co")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "YOUR_SERVICE_ROLE_KEY")

POLL_INTERVAL = 10        # seconds between polls when idle
AGENT_ID = socket.gethostname()  # identifies which machine ran the scan

# ============================================================
# Logging
# ============================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("kali-agent")


# ============================================================
# Supabase client
# ============================================================
def get_supabase() -> Client:
    return create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)


# ============================================================
# Scan dispatcher
# ============================================================
def claim_scan(sb: Client) -> Optional[dict]:
    """Atomically claim a pending scan by updating its status to running."""
    result = (
        sb.table("scan_results")
        .select("*")
        .eq("status", "pending")
        .order("created_at")
        .limit(1)
        .execute()
    )
    if not result.data:
        return None

    scan = result.data[0]
    scan_id = scan["id"]

    # Mark as running
    sb.table("scan_results").update({
        "status": "running",
        "agent_id": AGENT_ID,
    }).eq("id", scan_id).eq("status", "pending").execute()

    log.info(f"Claimed scan {scan_id}: {scan['name']} ({scan['target']}) via {scan['tool']}")
    return scan


def run_scan(scan: dict) -> dict:
    """Dispatch to the appropriate tool runner."""
    tool = scan.get("tool", "").upper()
    target = scan["target"]

    if tool == "NMAP":
        return run_nmap(target)
    elif tool == "NIKTO":
        return run_nikto(target)
    elif tool == "SQLMAP":
        return run_sqlmap(target)
    elif tool == "FFUF":
        return run_ffuf(target)
    elif tool == "FULL":
        return run_full_scan(target)
    else:
        return {"findings": [], "raw_output": f"Unknown tool: {tool}", "error": f"Unknown tool: {tool}"}


def complete_scan(sb: Client, scan_id: str, result: dict):
    """Upload findings and mark scan as completed."""
    findings = result.get("findings", [])
    raw_output = result.get("raw_output", "")
    error = result.get("error")

    critical = sum(1 for f in findings if f["severity"] == "critical")
    high = sum(1 for f in findings if f["severity"] == "high")
    medium = sum(1 for f in findings if f["severity"] == "medium")
    low = sum(1 for f in findings if f["severity"] == "low")
    total = len(findings)

    # Insert findings
    if findings:
        rows = [
            {
                "scan_result_id": scan_id,
                "title": f["title"],
                "severity": f["severity"],
                "description": f.get("description"),
                "url": f.get("url"),
                "port": f.get("port"),
                "service": f.get("service"),
                "tool": f.get("tool", ""),
                "details": f.get("details"),
                "discovered_at": datetime.now(timezone.utc).isoformat(),
            }
            for f in findings
        ]
        sb.table("scan_findings").insert(rows).execute()
        log.info(f"Inserted {total} findings for scan {scan_id}")

    # Update scan result
    update = {
        "status": "failed" if error else "completed",
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "raw_output": raw_output[:50000] if raw_output else None,  # cap size
        "error_message": error,
        "critical_count": critical,
        "high_count": high,
        "medium_count": medium,
        "low_count": low,
        "total_findings": total,
    }
    sb.table("scan_results").update(update).eq("id", scan_id).execute()
    log.info(f"Scan {scan_id} marked as {'failed' if error else 'completed'} ({total} findings)")


# ============================================================
# Tool Runners
# ============================================================

def run_command(cmd: list, timeout: int = 300) -> tuple[str, str, int]:
    """Run a shell command and return (stdout, stderr, returncode)."""
    log.info(f"Running: {' '.join(cmd)}")
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout}s", 1
    except FileNotFoundError as e:
        return "", f"Tool not found: {e}", 1
    except Exception as e:
        return "", str(e), 1


def run_nmap(target: str) -> dict:
    """Run nmap and parse open ports."""
    # -sV: version detection, -T4: faster, --open: only open ports
    cmd = ["nmap", "-sV", "-T4", "--open", "-oN", "-", target]
    stdout, stderr, rc = run_command(cmd, timeout=120)
    raw = stdout or stderr

    findings = []
    # Parse port lines: "80/tcp  open  http  Apache httpd 2.4"
    for line in stdout.splitlines():
        match = re.match(r"^(\d+)/(\w+)\s+open\s+(\S+)\s*(.*)", line)
        if match:
            port = int(match.group(1))
            proto = match.group(2)
            service = match.group(3)
            version = match.group(4).strip()

            severity = "info"
            if port in (21, 23, 111, 512, 513, 514, 2049):
                severity = "high"
            elif port in (22, 25, 53, 110, 143, 3389):
                severity = "medium"
            elif port in (80, 443, 8080, 8443):
                severity = "low"

            title = f"Open port {port}/{proto}: {service}"
            if version:
                title += f" ({version})"

            findings.append({
                "title": title,
                "severity": severity,
                "port": port,
                "service": f"{service} {version}".strip(),
                "description": f"Port {port}/{proto} is open running {service}. {version}",
                "tool": "NMAP",
                "details": line.strip(),
            })

    return {"findings": findings, "raw_output": raw}


def run_nikto(target: str) -> dict:
    """Run nikto and parse findings."""
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
        outfile = f.name

    cmd = ["nikto", "-h", target, "-output", outfile, "-Format", "txt", "-nointeractive"]
    stdout, stderr, rc = run_command(cmd, timeout=300)
    raw = stdout or stderr

    findings = []
    try:
        with open(outfile) as f:
            content = f.read()
        raw = content or raw

        # Parse "+ " prefixed finding lines
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("+ ") and not line.startswith("+ Target") and not line.startswith("+ Start"):
                text = line[2:].strip()
                if not text or len(text) < 10:
                    continue

                severity = "medium"
                text_lower = text.lower()
                if any(k in text_lower for k in ["sql injection", "xss", "remote code", "rce", "shell", "command injection"]):
                    severity = "critical"
                elif any(k in text_lower for k in ["authentication", "password", "credential", "admin", "backup", "config"]):
                    severity = "high"
                elif any(k in text_lower for k in ["header", "cookie", "missing", "outdated", "version"]):
                    severity = "low"

                url = None
                url_match = re.search(r"(https?://\S+)", text)
                if url_match:
                    url = url_match.group(1)

                findings.append({
                    "title": text[:120],
                    "severity": severity,
                    "description": text,
                    "url": url,
                    "tool": "NIKTO",
                    "details": line,
                })
    except Exception as e:
        log.warning(f"Could not parse nikto output: {e}")

    try:
        os.unlink(outfile)
    except Exception:
        pass

    return {"findings": findings, "raw_output": raw}


def run_sqlmap(target: str) -> dict:
    """Run sqlmap in batch mode."""
    cmd = [
        "sqlmap", "-u", target,
        "--batch",          # no interactive prompts
        "--level=2",
        "--risk=1",
        "--forms",          # test forms
        "--crawl=2",
        "--timeout=10",
        "--output-dir=/tmp/sqlmap_output",
        "--flush-session",
    ]
    stdout, stderr, rc = run_command(cmd, timeout=300)
    raw = (stdout + "\n" + stderr).strip()

    findings = []
    combined = stdout + "\n" + stderr

    # Check for injection found
    if "sql injection" in combined.lower() or "parameter" in combined.lower() and "vulnerable" in combined.lower():
        # Try to extract parameter info
        for line in combined.splitlines():
            if "parameter" in line.lower() and ("injectable" in line.lower() or "vulnerable" in line.lower()):
                findings.append({
                    "title": f"SQL Injection: {line.strip()[:120]}",
                    "severity": "critical",
                    "description": line.strip(),
                    "url": target,
                    "tool": "SQLMAP",
                    "details": line.strip(),
                })

    if not findings and ("tested" in combined.lower() or "scanning" in combined.lower()):
        findings.append({
            "title": "SQLMap scan completed — no injections found",
            "severity": "info",
            "description": "SQLMap completed its scan without finding SQL injection vulnerabilities.",
            "url": target,
            "tool": "SQLMAP",
            "details": raw[:500],
        })

    return {"findings": findings, "raw_output": raw}


def run_ffuf(target: str) -> dict:
    """Run ffuf for directory/content discovery."""
    # Use a common wordlist available on Kali
    wordlists = [
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    ]
    wordlist = None
    for wl in wordlists:
        if os.path.exists(wl):
            wordlist = wl
            break

    if not wordlist:
        return {
            "findings": [{
                "title": "FFUF: No wordlist found",
                "severity": "info",
                "description": "Install seclists: sudo apt install seclists",
                "tool": "FFUF",
            }],
            "raw_output": "No wordlist found. Install seclists: sudo apt install seclists",
        }

    base = target.rstrip("/")
    cmd = [
        "ffuf",
        "-u", f"{base}/FUZZ",
        "-w", wordlist,
        "-mc", "200,201,204,301,302,307,401,403",
        "-t", "50",         # 50 threads
        "-timeout", "10",
        "-of", "json",
        "-o", "/tmp/ffuf_out.json",
        "-c",
    ]
    stdout, stderr, rc = run_command(cmd, timeout=180)
    raw = (stdout + "\n" + stderr).strip()

    findings = []
    try:
        with open("/tmp/ffuf_out.json") as f:
            data = json.load(f)
        for r in data.get("results", []):
            status = r.get("status", 0)
            url = r.get("url", "")
            length = r.get("length", 0)

            severity = "info"
            if status in (200, 201) and any(k in url.lower() for k in ["admin", "backup", "config", ".env", "passwd", "secret"]):
                severity = "high"
            elif status in (200, 201):
                severity = "low"
            elif status == 401:
                severity = "medium"
            elif status == 403:
                severity = "info"

            findings.append({
                "title": f"[{status}] {url}",
                "severity": severity,
                "description": f"HTTP {status} - Content length: {length}",
                "url": url,
                "tool": "FFUF",
                "details": json.dumps(r),
            })
    except Exception as e:
        log.warning(f"Could not parse ffuf output: {e}")

    try:
        os.unlink("/tmp/ffuf_out.json")
    except Exception:
        pass

    return {"findings": findings, "raw_output": raw}


def run_full_scan(target: str) -> dict:
    """Run all tools and combine results."""
    all_findings = []
    raw_parts = []

    for tool_fn, name in [
        (run_nmap, "NMAP"),
        (run_nikto, "NIKTO"),
        (run_sqlmap, "SQLMAP"),
        (run_ffuf, "FFUF"),
    ]:
        log.info(f"[FULL] Running {name}...")
        try:
            res = tool_fn(target)
            all_findings.extend(res.get("findings", []))
            raw_parts.append(f"\n{'='*40}\n{name}\n{'='*40}\n{res.get('raw_output','')}")
        except Exception as e:
            log.warning(f"[FULL] {name} failed: {e}")
            raw_parts.append(f"\n{name}: ERROR - {e}")

    return {
        "findings": all_findings,
        "raw_output": "\n".join(raw_parts),
    }


# ============================================================
# Main loop
# ============================================================
def main():
    if SUPABASE_URL == "https://YOUR_PROJECT.supabase.co":
        log.error("Please configure SUPABASE_URL and SUPABASE_SERVICE_KEY before running!")
        log.error("Edit kali_agent.py or set environment variables.")
        sys.exit(1)

    log.info(f"Kali Agent starting | Agent ID: {AGENT_ID}")
    log.info(f"Connected to: {SUPABASE_URL}")
    log.info(f"Polling every {POLL_INTERVAL}s for pending scans...")
    log.info("-" * 50)

    sb = get_supabase()

    while True:
        try:
            scan = claim_scan(sb)
            if scan:
                scan_id = scan["id"]
                try:
                    result = run_scan(scan)
                    complete_scan(sb, scan_id, result)
                except Exception as e:
                    log.error(f"Scan {scan_id} failed with exception: {e}")
                    try:
                        sb.table("scan_results").update({
                            "status": "failed",
                            "completed_at": datetime.now(timezone.utc).isoformat(),
                            "error_message": str(e),
                        }).eq("id", scan_id).execute()
                    except Exception:
                        pass
            else:
                log.debug("No pending scans. Waiting...")
                time.sleep(POLL_INTERVAL)

        except KeyboardInterrupt:
            log.info("Agent stopped by user.")
            break
        except Exception as e:
            log.error(f"Unexpected error: {e}")
            time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
