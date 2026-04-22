import subprocess
import sys
import threading
import time


def run_streaming(cmd: list, timeout: int, label: str = "TOOL") -> tuple[str, int]:
    """
    Run a command, streaming each output line live to the terminal (stdout)
    while also collecting the full output to return.
    Returns (combined_output, return_code).
    """
    start = time.time()
    print(f"\n{'=' * 70}", flush=True)
    print(f"[{label}] Starting: {' '.join(cmd[:8])}{' ...' if len(cmd) > 8 else ''}", flush=True)
    print(f"{'=' * 70}", flush=True)

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError as e:
        msg = f"[{label}] Command not found: {e}"
        print(msg, flush=True)
        return msg, 127

    collected_lines: list[str] = []

    def reader():
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                line = line.rstrip("\n")
                collected_lines.append(line)
                print(f"[{label}] {line}", flush=True)
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
        msg = f"\n[{label}] TIMEOUT after {elapsed}s (limit {timeout}s)"
        print(msg, flush=True)
        collected_lines.append(msg)
        return "\n".join(collected_lines), -1

    t.join(timeout=10)
    elapsed = int(time.time() - start)
    rc = proc.returncode
    print(f"\n[{label}] Finished in {elapsed}s with exit code {rc}", flush=True)
    print(f"[{label}] Total output lines: {len(collected_lines)}", flush=True)
    print(f"{'=' * 70}\n", flush=True)

    return "\n".join(collected_lines), rc
