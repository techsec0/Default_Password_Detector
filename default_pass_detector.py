import paramiko
import ftplib
import socket
import json
import os
import sys

def load_credentials(filename="credentials_db.json"):
    if getattr(sys, 'frozen', False):  # Check if running as a packaged .exe
        filename = os.path.join(sys._MEIPASS, filename)  # Get path for bundled files
    with open(filename, 'r') as f:
        return json.load(f)

def check_ssh(ip, credentials):
    results = []
    for cred in credentials:
        username = cred["username"]
        password = cred["password"]
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=username, password=password, timeout=5)
            results.append((username, password))
            ssh.close()
        except Exception:
            continue
    return results

def check_ftp(ip, credentials):
    results = []
    for cred in credentials:
        username = cred["username"]
        password = cred["password"]
        try:
            with ftplib.FTP(ip, timeout=5) as ftp:
                ftp.login(user=username, passwd=password)
                results.append((username, password))
        except Exception:
            continue
    return results

def main(ip):
    credentials = load_credentials()
    result_log = []

    print(f"Scanning {ip} for default credentials...")

    try:
        socket.create_connection((ip, 22), timeout=3)
        ssh_results = check_ssh(ip, credentials.get("ssh", []))
        for r in ssh_results:
            result_log.append(f"SSH: {ip} - {r[0]}:{r[1]}")
    except Exception:
        pass

    try:
        socket.create_connection((ip, 21), timeout=3)
        ftp_results = check_ftp(ip, credentials.get("ftp", []))
        for r in ftp_results:
            result_log.append(f"FTP: {ip} - {r[0]}:{r[1]}")
    except Exception:
        pass

    with open("results.txt", "w") as f:
        for line in result_log:
            print(line)
            f.write(line + "\n")

    if not result_log:
        print("No default credentials detected.")
    else:
        print("Scan completed. Results saved in results.txt.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python default_pass_detector.py <target_ip>")
    else:
        main(sys.argv[1])
