#!/usr/bin/env python3
"""
LogGuard v2 – AutoBan Edition
Detects brute-force login attempts and automatically blocks suspicious IPs.

Author: Dilshad (https://github.com/cool5102)
"""

import re
import os
import csv
import argparse
import platform
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict

def parse_log(file_path, threshold, window):
    pattern = re.compile(r"Failed password.*from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)")
    fails = defaultdict(list)

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            match = pattern.search(line)
            if match:
                ip = match.group(1)
                ts_match = re.match(r"([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", line)
                if ts_match:
                    try:
                        ts = datetime.strptime(ts_match.group(1), "%b %d %H:%M:%S")
                        ts = ts.replace(year=datetime.now().year)
                        fails[ip].append(ts)
                    except ValueError:
                        pass

    suspicious = []
    for ip, times in fails.items():
        times.sort()
        for i in range(len(times)):
            start = times[i]
            window_end = start + timedelta(seconds=window)
            attempts = [t for t in times if start <= t <= window_end]
            if len(attempts) >= threshold:
                suspicious.append((ip, len(attempts), start.strftime("%H:%M:%S"), window_end.strftime("%H:%M:%S")))
                break
    return suspicious

def block_ip(ip):
    system = platform.system().lower()
    try:
        if "linux" in system or "darwin" in system:
            # Try UFW first
            if subprocess.call(["which", "ufw"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
                subprocess.run(["sudo", "ufw", "deny", "from", ip], check=True)
            else:
                subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        elif "windows" in system:
            subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", f"name=LogGuardBlock_{ip}", "dir=in", "action=block", f"remoteip={ip}"], check=True)
        print(f"[🔥] Blocked IP: {ip}")
        return True
    except Exception as e:
        print(f"[!] Failed to block {ip}: {e}")
        return False

def write_report(results):
    os.makedirs("results", exist_ok=True)
    filename = f"results/logguard_autoban_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["ip", "attempts", "start_time", "end_time"])
        writer.writerows(results)
    return filename

def main():
    parser = argparse.ArgumentParser(description="Detect and auto-block brute-force login attempts.")
    parser.add_argument("logfile", help="Path to log file (e.g., /var/log/auth.log)")
    parser.add_argument("--threshold", type=int, default=5, help="Failed attempts threshold (default 5)")
    parser.add_argument("--window", type=int, default=3600, help="Time window in seconds (default 3600)")
    parser.add_argument("--autoban", action="store_true", help="Enable automatic IP blocking")
    args = parser.parse_args()

    print(f"[+] Analyzing {args.logfile} …")
    results = parse_log(args.logfile, args.threshold, args.window)

    if not results:
        print("[✓] No brute-force patterns found.")
        return

    report = write_report(results)
    print(f"[✓] Suspicious IPs detected: {len(results)}")
    print(f"[+] Report saved to: {report}")

    if args.autoban:
        print("[⚙️] Auto-ban enabled. Blocking suspicious IPs…")
        for ip, *_ in results:
            block_ip(ip)
        print("[✓] All suspicious IPs processed.")

if __name__ == "__main__":
    main()
