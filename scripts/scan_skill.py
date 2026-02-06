#!/usr/bin/env python3
"""Scan skill files against VirusTotal API v3.

Accepts a skill directory or individual files. Computes SHA-256 hashes first
and checks if VT already has a report. Only uploads files that are unknown.
Outputs a JSON report with per-file verdicts and an overall pass/fail.

Environment:
    VT_API_KEY  – VirusTotal API key (required)

Usage:
    python scan_skill.py <path> [--wait <seconds>] [--threshold <int>]

    path        Skill directory or single file to scan
    --wait      Max seconds to wait for analysis (default 120)
    --threshold Min malicious detections to flag a file (default 1)
"""

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

try:
    import requests
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests", "-q", "--break-system-packages"])
    import requests

VT_BASE = "https://www.virustotal.com/api/v3"


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def vt_headers(api_key: str) -> dict:
    return {"x-apikey": api_key, "Accept": "application/json"}


def check_network(api_key: str) -> str | None:
    """Quick connectivity check to VT. Returns error message or None if OK."""
    try:
        r = requests.get(f"{VT_BASE}/files/unknownhashtest", headers=vt_headers(api_key), timeout=10)
        # 404 or 401 means we reached VT — network is fine
        return None
    except requests.exceptions.ProxyError:
        return (
            "\u274c Network error: Connection to virustotal.com blocked by proxy.\n"
            "   This environment restricts outbound network access.\n"
            "   Options:\n"
            "     \u2022 Run this skill in Claude Desktop or Claude Code (unrestricted network)\n"
            "     \u2022 Add virustotal.com to your allowed domains (Team/Enterprise plans)\n"
            "     \u2022 Use the mcp-virustotal MCP server instead (bypasses sandbox networking)"
        )
    except requests.exceptions.ConnectionError:
        return (
            "\u274c Network error: Cannot reach virustotal.com.\n"
            "   Check your internet connection or firewall settings."
        )
    except requests.exceptions.Timeout:
        return (
            "\u274c Network error: Connection to virustotal.com timed out.\n"
            "   The API may be temporarily unavailable. Try again later."
        )
    except Exception as e:
        return f"\u274c Network error: Unexpected failure connecting to virustotal.com: {e}"


def lookup_hash(api_key: str, file_hash: str) -> dict | None:
    """Check VT for an existing report by SHA-256."""
    try:
        r = requests.get(f"{VT_BASE}/files/{file_hash}", headers=vt_headers(api_key), timeout=30)
        if r.status_code == 200:
            return r.json().get("data", {}).get("attributes", {})
        return None
    except requests.exceptions.RequestException as e:
        print(f"  \u26a0 Network error during hash lookup: {e}", file=sys.stderr)
        return None


def upload_file(api_key: str, file_path: str) -> str | None:
    """Upload a file to VT and return the analysis ID."""
    headers = vt_headers(api_key)
    try:
        with open(file_path, "rb") as f:
            r = requests.post(f"{VT_BASE}/files", headers=headers, files={"file": f}, timeout=60)
        if r.status_code == 200:
            return r.json().get("data", {}).get("id")
        print(f"  \u26a0 Upload failed ({r.status_code}): {r.text[:200]}", file=sys.stderr)
        return None
    except requests.exceptions.RequestException as e:
        print(f"  \u26a0 Network error during upload: {e}", file=sys.stderr)
        return None


def poll_analysis(api_key: str, analysis_id: str, timeout: int = 120) -> dict | None:
    """Poll VT until analysis completes or timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(f"{VT_BASE}/analyses/{analysis_id}", headers=vt_headers(api_key), timeout=30)
            if r.status_code == 200:
                data = r.json().get("data", {})
                status = data.get("attributes", {}).get("status")
                if status == "completed":
                    return data.get("attributes", {})
        except requests.exceptions.RequestException as e:
            print(f"  \u26a0 Network error during poll: {e}", file=sys.stderr)
        time.sleep(15)
    return None


def evaluate(stats: dict, threshold: int) -> str:
    """Return 'clean', 'suspicious', or 'malicious' based on detection stats."""
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    if malicious >= threshold:
        return "malicious"
    if suspicious > 0:
        return "suspicious"
    return "clean"


def collect_files(path: str) -> list[str]:
    """Recursively collect all files under a path."""
    p = Path(path)
    if p.is_file():
        return [str(p)]
    files = []
    for f in sorted(p.rglob("*")):
        if f.is_file():
            files.append(str(f))
    return files


def scan(path: str, api_key: str, wait: int = 120, threshold: int = 1) -> dict:
    files = collect_files(path)
    if not files:
        return {"error": "No files found", "passed": False}

    # Pre-flight network check
    net_err = check_network(api_key)
    if net_err:
        print(net_err, file=sys.stderr)
        # Still return file hashes so MCP hybrid path can use them
        hash_only = []
        for fp in files:
            rel = os.path.relpath(fp, path) if os.path.isdir(path) else os.path.basename(fp)
            hash_only.append({"file": rel, "sha256": sha256_file(fp), "size": os.path.getsize(fp), "verdict": "skipped", "reason": "network unreachable"})
        return {"overall": "network_error", "passed": False, "files_scanned": len(hash_only), "results": hash_only, "network_error": net_err}

    results = []
    overall = "clean"

    for fp in files:
        rel = os.path.relpath(fp, path) if os.path.isdir(path) else os.path.basename(fp)
        file_hash = sha256_file(fp)
        size = os.path.getsize(fp)
        entry = {"file": rel, "sha256": file_hash, "size": size}

        print(f"  Checking {rel} ({file_hash[:12]}...)")

        # Step 1: check existing report
        attrs = lookup_hash(api_key, file_hash)
        if attrs:
            stats = attrs.get("last_analysis_stats", {})
            verdict = evaluate(stats, threshold)
            entry.update({"verdict": verdict, "stats": stats, "source": "existing_report"})
        else:
            # Step 2: upload if no report
            if size > 32 * 1024 * 1024:
                entry.update({"verdict": "skipped", "reason": "file >32MB, skipped"})
                results.append(entry)
                continue

            print(f"    Uploading to VirusTotal...")
            analysis_id = upload_file(api_key, fp)
            if not analysis_id:
                entry.update({"verdict": "error", "reason": "upload failed"})
                results.append(entry)
                overall = "error" if overall == "clean" else overall
                continue

            print(f"    Waiting for analysis (up to {wait}s)...")
            analysis = poll_analysis(api_key, analysis_id, timeout=wait)
            if analysis:
                stats = analysis.get("stats", {})
                verdict = evaluate(stats, threshold)
                entry.update({"verdict": verdict, "stats": stats, "source": "new_scan"})
            else:
                entry.update({"verdict": "pending", "reason": "analysis timed out", "analysis_id": analysis_id})

        verdict = entry.get("verdict", "unknown")
        if verdict == "malicious":
            overall = "malicious"
        elif verdict == "suspicious" and overall == "clean":
            overall = "suspicious"
        elif verdict in ("error", "pending") and overall == "clean":
            overall = verdict

        results.append(entry)

    passed = overall in ("clean",)
    return {"overall": overall, "passed": passed, "files_scanned": len(results), "results": results}


def scan_multiple(paths: list[str], api_key: str, wait: int = 120, threshold: int = 1) -> dict:
    """Scan multiple individual files or directories and merge results."""
    all_results = []
    overall = "clean"

    for p in paths:
        if not os.path.exists(p):
            all_results.append({"file": p, "verdict": "error", "reason": "path not found"})
            overall = "error" if overall == "clean" else overall
            continue
        report = scan(p, api_key, wait=wait, threshold=threshold)
        all_results.extend(report.get("results", []))
        v = report.get("overall", "clean")
        if v == "malicious":
            overall = "malicious"
        elif v == "suspicious" and overall == "clean":
            overall = "suspicious"
        elif v in ("error", "pending") and overall == "clean":
            overall = v

    passed = overall in ("clean",)
    return {"overall": overall, "passed": passed, "files_scanned": len(all_results), "results": all_results}


def main():
    parser = argparse.ArgumentParser(description="Scan skill files with VirusTotal")
    parser.add_argument("paths", nargs="+", help="Skill directory(s) or file(s) to scan")
    parser.add_argument("--wait", type=int, default=120, help="Max wait seconds per analysis (default 120)")
    parser.add_argument("--threshold", type=int, default=1, help="Min malicious detections to flag (default 1)")
    args = parser.parse_args()

    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        print("ERROR: VT_API_KEY environment variable not set.", file=sys.stderr)
        sys.exit(1)

    if len(args.paths) == 1:
        path = args.paths[0]
        if not os.path.exists(path):
            print(f"ERROR: Path not found: {path}", file=sys.stderr)
            sys.exit(1)
        print(f"\ud83d\udd0d Scanning: {path}")
        report = scan(path, api_key, wait=args.wait, threshold=args.threshold)
    else:
        print(f"\ud83d\udd0d Scanning {len(args.paths)} paths...")
        report = scan_multiple(args.paths, api_key, wait=args.wait, threshold=args.threshold)

    print(json.dumps(report, indent=2))

    if report.get("passed"):
        print("\n\u2705 PASSED — All files clean.")
    elif report.get("overall") == "network_error":
        print(f"\n\u26a0\ufe0f  SCAN INCOMPLETE — Could not reach VirusTotal.")
        print("   File hashes have been computed and are shown above.")
        print("   Use these hashes with the MCP server or check manually at virustotal.com")
        sys.exit(3)
    else:
        print(f"\n\u274c FAILED — Overall verdict: {report.get('overall')}")
        sys.exit(2)


if __name__ == "__main__":
    main()
