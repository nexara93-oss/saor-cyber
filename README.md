# SAQR - Security Scanner & Exploitation Tool

**Version:** 1.0  
**Author:** Black  
**Language:** Python 3  
**Platform:** Linux / Windows / macOS

---

## Overview

SAQR is a Python-based security scanner designed for penetration testing and vulnerability assessment. It performs full port scanning, detects known CVEs, attempts automatic exploitation, and generates a detailed report.

> **Legal Notice:** Use this tool only on systems you own or have explicit written permission to test. Unauthorized scanning and exploitation is illegal.

---

## Features

| Feature | Description |
|---------|-------------|
| **Full Port Scan** | Scans all 65,535 TCP ports |
| **Multi-threaded** | Up to 500 concurrent threads for speed |
| **Banner Grabbing** | Retrieves service banners from open ports |
| **Service Detection** | Identifies services by port and banner |
| **CVE Detection** | Matches banners against a vulnerability database |
| **Auto Exploitation** | Attempts exploitation for supported CVEs |
| **JSON Report** | Saves full results to a JSON file |
| **Terminal Report** | Displays a formatted summary in the terminal |
| **Color Output** | Highlights findings by severity |

---

## How It Works

### 1. Port Scanning
The tool scans all TCP ports from 1 to 65535 using a thread pool. Each open port is logged with the time it was discovered.

### 2. Banner Grabbing
For each open port, SAQR connects and attempts to retrieve a service banner:
- Sends `GET / HTTP/1.0` for HTTP/HTTPS ports
- Reads raw banners for SSH, FTP, and database ports
- Wraps sockets with SSL for HTTPS ports

### 3. Vulnerability Detection
Each banner is matched against a built-in vulnerability database (`VULN_DB`). Each entry contains:
- CVE ID
- Affected service
- Port
- Banner pattern
- Description
- Severity
- Exploit availability

### 4. Exploitation
For CVEs marked as exploitable, SAQR attempts automatic exploitation:
- **Apache Path Traversal (CVE-2021-41773)** — reads `/etc/passwd`
- **Fortinet Path Traversal (CVE-2018-13379)** — reads `sslvpn_websession`
- Other CVEs require manual exploitation

### 5. Reporting
Two reports are generated:
- **Terminal report** — formatted summary with colors
- **JSON file** — full structured data (`report_<IP>_<timestamp>.json`)

---

## Installation

### Requirements
- Python 3.7+
- No external dependencies (uses only standard library)

### Setup
```bash
git clone <repo>
cd saqr
chmod +x saqr.py
