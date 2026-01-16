# File: default_pass_detector_v2.py
# Final Python scanner:
# - Reads an IP list file (one IP per line) or single IP argument
# - Skips invalid ips, reports skipped ones
# - Scans SSH and FTP using paramiko/ftplib
# - ThreadPool with configurable max_threads
# - Writes results.txt and prints lines like "SSH: ip - user:pass"

import sys
import os
import json
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

try:
    import paramiko
except Exception:
    print("paramiko not found, installing...")
    try:
        install("paramiko")
        import paramiko
    except Exception as e:
        print("Failed to install paramiko:", e)
        sys.exit(2)

import ftplib

def load_credentials(filename):
    if getattr(sys, 'frozen', False):
        filename = os.path.join(sys._MEIPASS, filename)
    with open(filename, 'r') as f:
        return json.load(f)

def check_ssh(ip, credentials, timeout_per_conn=5):
    results = []
    for cred in credentials:
        username = cred.get("username")
        password = cred.get("password")
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=username, password=password, timeout=timeout_per_conn)
            results.append((username, password))
            ssh.close()
        except Exception:
            continue
    return results

def check_ftp(ip, credentials, timeout_per_conn=5):
    results = []
    for cred in credentials:
        username = cred.get("username")
        password = cred.get("password")
        try:
            with ftplib.FTP() as ftp:
                ftp.connect(ip, 21, timeout=timeout_per_conn)
                ftp.login(user=username, passwd=password)
                results.append((username, password))
        except Exception:
            continue
    return results

def port_is_open(ip, port, timeout=3):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False

def scan_one_ip(ip, credentials, timeout_per_conn):
    out = []
    try:
        if port_is_open(ip, 22, timeout=3):
            ssh_results = check_ssh(ip, credentials.get("ssh", []), timeout_per_conn)
            for u,p in ssh_results:
                out.append(f"SSH: {ip} - {u}:{p}")
        if port_is_open(ip, 21, timeout=3):
            ftp_results = check_ftp(ip, credentials.get("ftp", []), timeout_per_conn)
            for u,p in ftp_results:
                out.append(f"FTP: {ip} - {u}:{p}")
    except Exception:
        pass
    return out

def read_ip_list_or_file(arg):
    if os.path.isfile(arg):
        ips = []
        with open(arg, 'r') as f:
            for line in f:
                l = line.strip()
                if l:
                    ips.append(l)
        return ips
    else:
        return [arg]

def is_invalid_or_special(ip):
    # Basic IPv4 validation and skip special addresses and last-octet 0/255
    try:
        socket.inet_aton(ip)
    except Exception:
        return True, "Invalid IP format"
    if ip == "0.0.0.0" or ip == "255.255.255.255":
        return True, "Reserved special address"
    parts = ip.split(".")
    try:
        last = int(parts[3])
        if last == 0:
            return True, "Network address (last octet 0)"
        if last == 255:
            return True, "Broadcast address (last octet 255)"
    except Exception:
        pass
    return False, ""

def main():
    if len(sys.argv) < 2:
        print("Usage: python default_pass_detector_v2.py <ip_or_iplist_file> [credentials_file] [timeout_seconds] [max_threads]")
        sys.exit(1)

    target = sys.argv[1]
    creds_file = sys.argv[2] if len(sys.argv) >= 3 else "credentials_db.json"
    timeout_seconds = int(sys.argv[3]) if len(sys.argv) >= 4 else 30
    max_threads = int(sys.argv[4]) if len(sys.argv) >= 5 else 5

    try:
        credentials = load_credentials(creds_file)
    except Exception as e:
        print("Failed to load credentials file:", e)
        sys.exit(2)

    try:
        ip_list = read_ip_list_or_file(target)
    except Exception as e:
        print("Failed to read IP list:", e)
        sys.exit(3)

    if not ip_list:
        print("No IPs to scan.")
        return

    valid_ips = []
    for ip in ip_list:
        bad, reason = is_invalid_or_special(ip)
        if bad:
            print(f"Skipping IP {ip}: {reason}")
            continue
        valid_ips.append(ip)

    if not valid_ips:
        print("No valid IPv4 addresses found to scan.")
        return

    print(f"Starting threaded scan on {len(valid_ips)} IP(s) with {max_threads} threads...")
    lock = threading.Lock()
    results = []

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scan_one_ip, ip, credentials, timeout_seconds): ip for ip in valid_ips}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                res = future.result()
                for line in res:
                    print(line)
                    with lock:
                        results.append(line)
            except Exception as exc:
                print(f"Error scanning {ip}: {exc}")

    # Save results to results.txt (overwrite)
    try:
        with open("results.txt", "w") as f:
            for line in results:
                f.write(line + "\n")
    except Exception as e:
        print("Failed to write results.txt:", e)

    if not results:
        print("No default credentials detected.")
    else:
        print("Scan completed. Results saved in results.txt.")

if __name__ == "__main__":
    main()
