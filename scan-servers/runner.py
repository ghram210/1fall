import subprocess
import threading
import time
import re

PROGRESS_PATTERN = re.compile(r"::\s*Progress:\s*\[")


def run_streaming(cmd: list, timeout: int, label: str = "TOOL") -> tuple[str, int]:
    """
    Run a command, streaming each output line live to the terminal (stdout)
    while also collecting the full output to return.
    Handles both \\n and \\r line endings (e.g. FFUF progress bar).
    Returns (combined_output, return_code).
    """
    start = time.time()
    print(f"\n{'=' * 70}", flush=True)
    print(f"[{label}] Starting: {' '.join(cmd)}", flush=True)
    print(f"{'=' * 70}", flush=True)

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        )
    except FileNotFoundError as e:
        msg = f"[{label}] Command not found: {e}"
        print(msg, flush=True)
        return msg, 127

    collected_lines: list[str] = []
    last_progress = ""

    def reader():
        nonlocal last_progress
        assert proc.stdout is not None
        buf = b""
        try:
            while True:
                chunk = proc.stdout.read(512)
                if not chunk:
                    break
                buf += chunk
                while True:
                    nl = buf.find(b"\n")
                    cr = buf.find(b"\r")
                    if nl == -1 and cr == -1:
                        break
                    if nl == -1:
                        sep, end = cr, cr + 1
                    elif cr == -1:
                        sep, end = nl, nl + 1
                    else:
                        sep, end = (nl, nl + 1) if nl < cr else (cr, cr + 1)

                    raw_line = buf[:sep].decode("utf-8", errors="replace").strip()
                    buf = buf[end:]

                    if not raw_line:
                        continue

                    if PROGRESS_PATTERN.search(raw_line):
                        last_progress = raw_line
                        continue

                    collected_lines.append(raw_line)
                    print(f"[{label}] {raw_line}", flush=True)

            if buf:
                raw_line = buf.decode("utf-8", errors="replace").strip()
                if raw_line and not PROGRESS_PATTERN.search(raw_line):
                    collected_lines.append(raw_line)
                    print(f"[{label}] {raw_line}", flush=True)

        except Exception as e:
            collected_lines.append(f"[reader error] {e}")

    t = threading.Thread(target=reader, daemon=True)
    t.start()

    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=5)
        except Exception:
            pass
        t.join(timeout=5)
        elapsed = int(time.time() - start)
        if last_progress:
            print(f"[{label}] Last progress: {last_progress}", flush=True)
        msg = f"\n[{label}] TIMEOUT after {elapsed}s (limit {timeout}s)"
        print(msg, flush=True)
        collected_lines.append(msg)
        return "\n".join(collected_lines), -1

    t.join(timeout=10)
    elapsed = int(time.time() - start)
    rc = proc.returncode

    if last_progress:
        print(f"[{label}] {last_progress}", flush=True)

    print(f"\n[{label}] Finished in {elapsed}s with exit code {rc}", flush=True)
    print(f"[{label}] Total output lines: {len(collected_lines)}", flush=True)
    print(f"{'=' * 70}\n", flush=True)

    return "\n".join(collected_lines), rc
