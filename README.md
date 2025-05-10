# Default Password Detector

This tool scans a target IP address for services (SSH and FTP) that use default credentials. It's designed for system administrators, penetration testers, and compliance auditors.

## 🔧 Features

- Checks SSH and FTP for known default login pairs
- Easy-to-read output saved to `results.txt`
- Fast and simple command-line interface

## 🖥 Usage

```bash
python default_pass_detector.py <target_ip>
