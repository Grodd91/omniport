#!/usr/bin/env python3
"""
OmniPort - Comprehensive Network and Security Scanner with 100+ Features

Features:
- Port scanning (TCP/UDP)
- Service fingerprinting
- Vulnerability detection
- Network analysis
- Web application testing
- Monitoring and reporting
"""

import argparse
import sys
import socket
import time
import requests
import json
import csv
import smtplib
import sqlite3
import logging
import ssl
import ipaddress
import random
import whois
import yaml
import shodan
import re
import subprocess
import netifaces
import os
import hashlib
import platform
from email.message import EmailMessage
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style
from tqdm import tqdm
from urllib.parse import urlparse
from collections import defaultdict
from typing import List, Dict, Tuple, Optional, Union

# Constants
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 8080]
TOP_100_PORTS = [7, 20, 21, 22, 23, 25, 26, 53, 67, 68, 69, 80, 81, 88, 106, 110, 
                111, 113, 119, 123, 135, 137, 138, 139, 143, 161, 179, 194, 389, 
                427, 443, 445, 465, 514, 515, 543, 544, 548, 554, 587, 631, 646, 
                873, 902, 990, 993, 995, 1080, 1099, 1158, 1433, 1434, 1521, 1677, 
                1723, 1755, 1863, 2049, 2100, 2103, 2121, 2222, 2301, 2383, 2638, 
                2967, 3000, 3128, 3268, 3306, 3389, 3396, 3689, 3690, 3703, 3986, 
                4000, 4001, 4045, 4899, 5000, 5001, 5003, 5060, 5101, 5190, 5357, 
                5432, 5555, 5631, 5666, 5800, 5900, 5984, 6000, 6379, 7001, 7070, 
                8000, 8008, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 11211, 27017, 
                27018, 28015, 49152]

COMMON_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "curl/7.68.0",
    "Wget/1.21",
    "python-requests/2.31.0",
    "Mozilla/5.0 (X11; Linux x86_64)"
]

COMMON_ENDPOINTS = [
    "/admin", "/login", "/register", "/dashboard", "/config",
    "/setup", "/status", "/api", "/.git", "/.env", "/.DS_Store",
    "/server-status", "/phpinfo.php", "/backup", "/hidden"
]

SECURITY_HEADERS = [
    "x-frame-options",
    "content-security-policy",
    "x-xss-protection",
    "strict-transport-security",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy"
]

PHISHING_KEYWORDS = [
    "login", "verify", "secure", "confirm", "validate", "account", "bank"
]

WEAK_BANNER_PATTERNS = [
    "test", "open", "public", "demo", "ftp", "telnet", "vulnerable", "outdated",
    "apache/2.2", "iis/6.0", "nginx/1.0", "vsftpd 2.3.4", "proftpd", "ssh-1.99"
]

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('omniport.log'),
        logging.StreamHandler()
    ]
)

class OmniPortScanner:
    """Main scanner class with all functionality"""
    
    def __init__(self):
        self.version = "1.0.0"
        self.scan_id = hashlib.md5(str(datetime.now()).encode()).hexdigest()[:8]
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': random.choice(COMMON_USER_AGENTS)})
        
    # Core scanning functions
    def scan_tcp_port(self, host: str, port: int, banner_grab: bool = False, retry: int = 1) -> Optional[Tuple[int, str]]:
        """Scan a single TCP port with optional banner grabbing"""
        for _ in range(retry):
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                if result == 0:
                    banner = ""
                    if banner_grab:
                        try:
                            sock.sendall(b'\r\n')
                            banner = sock.recv(1024).decode(errors='ignore').strip()
                        except:
                            banner = ""
                    sock.close()
                    return (port, banner)
            except Exception:
                continue
            finally:
                if sock:
                    sock.close()
        return None

    def scan_udp_port(self, host: str, port: int, banner_grab: bool = False, retry: int = 1) -> Optional[Tuple[int, str]]:
        """Scan a single UDP port"""
        for _ in range(retry):
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(1)
                sock.sendto(b'', (host, port))
                data, _ = sock.recvfrom(1024)
                return (port, data.decode(errors='ignore').strip() if banner_grab else "")
            except socket.timeout:
                continue
            except Exception:
                continue
            finally:
                if sock:
                    sock.close()
        return None

    def scan_ports(self, host: str, ports: List[int], protocol: str = 'tcp', max_threads: int = 100, 
                  banner_grab: bool = False, rate_limit: int = 0, retry: int = 1, 
                  stealth: bool = False, fuzzy: bool = False) -> List[Tuple[int, str]]:
        """Scan multiple ports with threading support"""
        open_ports = []
        scan_func = lambda h, p: self.scan_tcp_port(h, p, banner_grab, retry) if protocol == 'tcp' else self.scan_udp_port(h, p, banner_grab, retry)

        if fuzzy:
            fuzzy_set = set()
            for port in ports:
                fuzzy_set.update(range(max(1, port - 10), min(65535, port + 11)))
            ports = list(fuzzy_set)

        if stealth:
            random.shuffle(ports)

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = []
            for port in ports:
                futures.append(executor.submit(scan_func, host, port))
                if rate_limit > 0:
                    time.sleep(1 / rate_limit)
            for future in tqdm(futures, desc=f"Scanning {host}", unit="port"):
                result = future.result()
                if result:
                    open_ports.append(result)
        return open_ports

    def scan_network_subnet(self, subnet: str, ports: List[int], **kwargs) -> Dict[str, List[Tuple[int, str]]]:
        """Scan a network subnet for open ports"""
        hosts = [str(ip) for ip in ipaddress.IPv4Network(subnet, strict=False)]
        results = {}
        for host in hosts:
            print(Fore.BLUE + f"\n{host}:")
            open_ports = self.scan_ports(host, ports, **kwargs)
            if open_ports:
                results[host] = open_ports
        return results

    # Service and OS detection
    def get_service_name(self, port: int, protocol: str) -> str:
        """Get service name by port number"""
        try:
            return socket.getservbyport(port, protocol)
        except:
            return "unknown"

    def fingerprint_os(self, ip: str) -> str:
        """Basic OS fingerprinting using TTL"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(1)
            sock.sendto(b"\x08\x00\x00\x00\x00\x00\x00\x00", (ip, 0))
            data, addr = sock.recvfrom(1024)
            ttl = data[8]
            if ttl >= 128:
                return "Windows (probably)"
            elif ttl >= 64:
                return "Linux/Unix (probably)"
            else:
                return "Unknown OS"
        except Exception:
            return "Unable to determine OS"

    def classify_device_type(self, banner: str, ttl: int) -> str:
        """Classify device type based on banner and TTL"""
        if not banner:
            return "Unknown"
        banner_lower = banner.lower()
        if "mikrotik" in banner_lower or ttl in [127, 128]:
            return "Router"
        elif "windows" in banner_lower:
            return "Windows host"
        elif "debian" in banner_lower or "ubuntu" in banner_lower:
            return "Linux server"
        elif "printer" in banner_lower or "hp" in banner_lower:
            return "Printer/Office device"
        elif "nas" in banner_lower or "synology" in banner_lower:
            return "File server/NAS"
        return "Generic network device"

    # HTTP/Web functions
    def fetch_http_headers(self, host: str, port: int = 80) -> Dict[str, str]:
        """Fetch HTTP headers from a web server"""
        try:
            url = f"http://{host}:{port}" if port != 443 else f"https://{host}:{port}"
            resp = self.session.get(url, timeout=2)
            return dict(resp.headers)
        except:
            return {}

    def check_security_headers(self, headers: Dict[str, str]) -> Dict[str, Optional[str]]:
        """Check for important security headers"""
        return {key: headers.get(key, None) for key in SECURITY_HEADERS}

    def brute_force_endpoints(self, host: str, port: int = 80, wordlist: List[str] = None, 
                            wordlist_path: str = None) -> List[Tuple[str, int]]:
        """Brute force common web endpoints"""
        if wordlist_path:
            try:
                with open(wordlist_path, 'r') as f:
                    wordlist = [line.strip() for line in f if line.strip()]
            except Exception as e:
                logging.error(f"Error loading wordlist: {e}")
                return []
        if not wordlist:
            wordlist = COMMON_ENDPOINTS

        scheme = "https" if port == 443 else "http"
        results = []
        for path in wordlist:
            url = f"{scheme}://{host}:{port}{path}"
            try:
                resp = self.session.get(url, timeout=2)
                if resp.status_code < 400:
                    results.append((path, resp.status_code))
            except:
                continue
        return results

    def detect_http_redirects(self, url: str) -> Tuple[List[requests.Response], str]:
        """Detect HTTP redirects"""
        try:
            resp = self.session.get(url, timeout=3, allow_redirects=True)
            return resp.history, resp.url
        except:
            return [], url

    def check_hsts(self, host: str) -> bool:
        """Check for HSTS header"""
        try:
            resp = self.session.get(f"https://{host}", timeout=3)
            return 'strict-transport-security' in resp.headers
        except:
            return False

    def send_custom_headers(self, host: str, port: int = 80, headers: Dict[str, str] = None) -> Tuple[Optional[int], Dict[str, str], str]:
        """Send custom HTTP headers to a server"""
        if headers is None:
            headers = {"User-Agent": "Mozilla/5.0 (custom)"}
        scheme = "https" if port == 443 else "http"
        url = f"{scheme}://{host}:{port}" 
        try:
            resp = self.session.get(url, headers=headers, timeout=3)
            return resp.status_code, dict(resp.headers), resp.text[:200]
        except Exception as e:
            return None, {}, str(e)

    def check_cors_policy(self, headers: Dict[str, str]) -> str:
        """Check CORS policy from headers"""
        origin = headers.get("access-control-allow-origin")
        return origin if origin else "None"

    # SSL/TLS functions
    def fetch_tls_certificate(self, host: str, port: int = 443) -> Dict:
        """Fetch TLS certificate details"""
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.settimeout(2)
                s.connect((host, port))
                cert = s.getpeercert()
            return cert
        except:
            return {}

    def check_tls_validity(self, cert: Dict) -> bool:
        """Check if TLS certificate is valid"""
        try:
            not_before = datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
            not_after = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
            now = datetime.utcnow()
            return not_before <= now <= not_after
        except:
            return False

    def get_ja3_hash(self, host: str, port: int = 443) -> str:
        """Get JA3 TLS fingerprint"""
        try:
            from ja3 import get_ja3_hash
            return get_ja3_hash(host, port)
        except ImportError:
            return "JA3 library not installed. Use: pip install ja3"
        except Exception as e:
            return f"JA3 error: {e}"

    # Vulnerability detection
    def is_weak_banner(self, banner: str) -> bool:
        """Detect weak or suspicious service banners"""
        if not banner:
            return False
        return any(pat in banner.lower() for pat in WEAK_BANNER_PATTERNS)

    def match_known_cves(self, banner: str) -> Optional[str]:
        """Match banners to known vulnerabilities"""
        if not banner:
            return None
        banner = banner.lower()
        if "vsftpd 2.3.4" in banner:
            return "CVE-2011-2523"
        elif "apache/2.2" in banner:
            return "CVE-2017-5638"
        elif "iis/6.0" in banner:
            return "CVE-2017-7269"
        elif "ssh-1.99" in banner:
            return "CVE-2001-0144"
        return None

    def detect_honeypot(self, ttl: int, banner: str, threshold: float = 0.5) -> bool:
        """Heuristically detect honeypots"""
        suspicion = 0
        if ttl < 40:
            suspicion += 0.5
        if banner and "cowrie" in banner.lower():
            suspicion += 0.5
        return suspicion >= threshold

    # Network utilities
    def get_ttl(self, host: str) -> int:
        """Get TTL value for a host"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((host, 80))
            ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
            sock.close()
            return ttl
        except:
            return -1

    def run_traceroute(self, host: str) -> str:
        """Run traceroute to a host"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(["tracert", host], capture_output=True, text=True, timeout=10)
            else:
                result = subprocess.run(["traceroute", host], capture_output=True, text=True, timeout=10)
            return result.stdout
        except Exception as e:
            return f"Traceroute error: {e}"

    def detect_upnp_services(self, timeout: int = 2) -> List[Tuple[str, str]]:
        """Detect UPnP services on the network"""
        upnp_discovery_msg = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            "MX: 1\r\n"
            "ST: ssdp:all\r\n"
            "\r\n"
        ).encode("utf-8")

        devices = []

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.settimeout(timeout)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.sendto(upnp_discovery_msg, ("239.255.255.250", 1900))

            while True:
                try:
                    data, addr = sock.recvfrom(1024)
                    devices.append((addr[0], data.decode(errors="ignore")))
                except socket.timeout:
                    break
        except Exception as e:
            return [("UPnP Error", str(e))]
        finally:
            sock.close()

        return devices

    def is_ipv6(self, address: str) -> bool:
        """Check if address is IPv6"""
        try:
            socket.inet_pton(socket.AF_INET6, address)
            return True
        except socket.error:
            return False

    def list_interfaces(self) -> List[str]:
        """List available network interfaces"""
        try:
            return netifaces.interfaces()
        except Exception as e:
            return [f"Error getting interfaces: {e}"]

    def scan_with_proxy(self, url: str, proxy_url: str) -> Tuple[Optional[int], str]:
        """Scan through a proxy"""
        try:
            proxies = {
                "http": proxy_url,
                "https": proxy_url
            }
            resp = self.session.get(url, proxies=proxies, timeout=5)
            return resp.status_code, resp.text[:200]
        except Exception as e:
            return None, str(e)

    def query_netbios(self, ip: str) -> str:
        """Query NetBIOS name"""
        try:
            from impacket.nmb import NetBIOS
            bios = NetBIOS()
            name = bios.queryIPForName(ip, timeout=2)
            bios.close()
            return name if name else "No NetBIOS response"
        except ImportError:
            return "Install impacket: pip install impacket"
        except Exception as e:
            return f"NetBIOS error: {e}"

    # Information gathering
    def get_whois_info(self, domain: str) -> str:
        """Get WHOIS information for a domain"""
        try:
            data = whois.whois(domain)
            return data.text if hasattr(data, 'text') else str(data)
        except Exception as e:
            return f"WHOIS error: {e}"

    def get_shodan_info(self, ip: str, api_key: str) -> Union[Dict, str]:
        """Get Shodan information for an IP"""
        try:
            api = shodan.Shodan(api_key)
            result = api.host(ip)
            return result
        except Exception as e:
            return f"Shodan error: {e}"

    def get_dns_records(self, domain: str, record_type: str = 'A') -> List[str]:
        """Get DNS records for a domain"""
        try:
            import dns.resolver
            answers = dns.resolver.resolve(domain, record_type)
            return [str(r) for r in answers]
        except Exception as e:
            return [f"DNS error: {e}"]

    # Monitoring and reporting
    def monitor_network_activity(self, host: str, ports: List[int], protocol: str, 
                               interval: int, email_cfg: Dict = None, last_ports: List = None):
        """Monitor network ports for changes"""
        try:
            while True:
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                open_ports = self.scan_ports(host, ports, protocol=protocol)
                changed = open_ports != last_ports
                print(Fore.CYAN + f"[{timestamp}] Open ports:")
                for port, _ in open_ports:
                    print(Fore.GREEN + f"  - {port} ({self.get_service_name(port, protocol)})")
                if changed and email_cfg:
                    self.send_email_report(
                        subject="Port monitoring change detected",
                        body="Changed open ports:",
                        **email_cfg
                    )
                last_ports = open_ports
                time.sleep(interval)
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\nMonitoring stopped.")

    def send_email_report(self, smtp_server: str, smtp_user: str, smtp_pass: str, 
                         to_email: str, subject: str, body: str):
        """Send email report"""
        try:
            msg = EmailMessage()
            msg['From'] = smtp_user
            msg['To'] = to_email
            msg['Subject'] = subject
            msg.set_content(body)

            with smtplib.SMTP_SSL(smtp_server, 465) as server:
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)
            print(Fore.CYAN + "\nReport sent via email.")
        except Exception as e:
            print(Fore.RED + f"\nEmail error: {e}")

    def save_to_sqlite(self, db_path: str, host: str, protocol: str, open_ports: List[Tuple[int, str]]):
        """Save scan results to SQLite database"""
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS scans 
                    (timestamp TEXT, host TEXT, protocol TEXT, port INTEGER, service TEXT, banner TEXT)''')
        for port, banner in open_ports:
            service = self.get_service_name(port, protocol)
            c.execute("INSERT INTO scans VALUES (?,?,?,?,?,?)", 
                     (datetime.now().isoformat(), host, protocol, port, service, banner))
        conn.commit()
        conn.close()
        logging.info(f"Saved {len(open_ports)} results to {db_path}")

    def save_to_ndjson(self, filepath: str, host: str, port_data: List[Tuple[int, str]]):
        """Save results to NDJSON file"""
        with open(filepath, 'a') as f:
            for port, banner in port_data:
                obj = {
                    "timestamp": datetime.utcnow().isoformat(),
                    "host": host,
                    "port": port,
                    "service": self.get_service_name(port, 'tcp'),
                    "banner": banner
                }
                f.write(json.dumps(obj) + '\n')

    # Additional security checks
    def check_http_methods(self, url: str) -> List[str]:
        """Check allowed HTTP methods"""
        try:
            resp = self.session.request('OPTIONS', url, timeout=3)
            return resp.headers.get('allow', '').split(',')
        except:
            return []

    def check_clickjacking(self, headers: Dict[str, str]) -> bool:
        """Check for clickjacking protection"""
        return 'x-frame-options' in headers

    def check_xss_protection(self, headers: Dict[str, str]) -> bool:
        """Check for XSS protection headers"""
        return 'x-xss-protection' in headers

    def check_content_type_options(self, headers: Dict[str, str]) -> bool:
        """Check for content type options header"""
        return 'x-content-type-options' in headers

    def check_csp(self, headers: Dict[str, str]) -> bool:
        """Check for Content Security Policy"""
        return 'content-security-policy' in headers

    def detect_phishing_endpoints(self, html: str) -> List[str]:
        """Detect potential phishing endpoints"""
        matches = []
        for keyword in PHISHING_KEYWORDS:
            if re.search(fr'{keyword}', html, re.IGNORECASE):
                matches.append(keyword)
        return matches

    def extract_jwt_tokens(self, html: str) -> List[str]:
        """Extract JWT tokens from HTML"""
        pattern = re.compile(r"eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+")
        return pattern.findall(html)

    def check_sql_injection(self, url: str) -> bool:
        """Basic SQL injection test"""
        try:
            test_payload = "' OR '1'='1"
            resp = self.session.get(f"{url}?id={test_payload}", timeout=3)
            return "error in your SQL syntax" in resp.text.lower()
        except:
            return False

    def check_xss_vulnerability(self, url: str) -> bool:
        """Basic XSS test"""
        try:
            test_payload = "<script>alert('XSS')</script>"
            resp = self.session.get(f"{url}?q={test_payload}", timeout=3)
            return test_payload in resp.text
        except:
            return False

    # Network mapping
    def discover_local_network(self) -> List[str]:
        """Discover devices on local network"""
        local_ip = socket.gethostbyname(socket.gethostname())
        network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
        return [str(host) for host in network.hosts()]

    def ping_sweep(self, network: str, timeout: int = 1) -> List[str]:
        """Perform ping sweep on a network"""
        hosts = []
        for ip in ipaddress.IPv4Network(network, strict=False).hosts():
            ip_str = str(ip)
            if self.is_host_alive(ip_str, timeout):
                hosts.append(ip_str)
        return hosts

    def is_host_alive(self, host: str, timeout: int = 1) -> bool:
        """Check if host is alive using ICMP ping"""
        try:
            if platform.system() == "Windows":
                cmd = ['ping', '-n', '1', '-w', str(timeout*1000), host]
            else:
                cmd = ['ping', '-c', '1', '-W', str(timeout), host]
            
            subprocess.run(cmd, 
                         stdout=subprocess.DEVNULL, 
                         stderr=subprocess.DEVNULL, 
                         check=True)
            return True
        except:
            return False

    # Utility functions
    def parse_ports_input(self, user_input: str, top_ports: List[int] = None) -> List[int]:
        """Parse user input for port ranges"""
        if user_input == 'top' and top_ports:
            return top_ports
        user_input = user_input.strip()
        if user_input.lower() == 'all':
            return list(range(1, 65536))
        elif '-' in user_input:
            try:
                start, end = map(int, user_input.split('-'))
                return list(range(start, end + 1))
            except ValueError:
                print("Invalid port range. Use format like 20-80.", file=sys.stderr)
                return []
        elif ',' in user_input:
            ports = []
            for part in user_input.split(','):
                part = part.strip()
                if part.isdigit():
                    ports.append(int(part))
                else:
                    print(f"Skipping invalid port: {part}", file=sys.stderr)
            return ports
        elif user_input.isdigit():
            return [int(user_input)]
        else:
            print("Invalid port format. Use number, range, or list.", file=sys.stderr)
            return []

    def resolve_hostname(self, hostname: str) -> Optional[str]:
        """Resolve hostname to IP address"""
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None

    def get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def get_external_ip(self) -> str:
        """Get external/public IP address"""
        try:
            resp = self.session.get('https://api.ipify.org', timeout=3)
            return resp.text
        except:
            return "Unable to determine"

    def generate_report(self, results: Dict, format: str = 'text') -> str:
        """Generate scan report in specified format"""
        if format == 'json':
            return json.dumps(results, indent=2)
        elif format == 'csv':
            output = "Host,Port,Service,Banner\n"
            for host, ports in results.items():
                for port, banner in ports:
                    service = self.get_service_name(port, 'tcp')
                    output += f"{host},{port},{service},\"{banner}\"\n"
            return output
        else:  # text
            output = ""
            for host, ports in results.items():
                output += f"\n{host}:\n"
                for port, banner in ports:
                    service = self.get_service_name(port, 'tcp')
                    output += f"  {port}: {service} - {banner}\n"
            return output

    def run_scheduled_scan(self, host: str, ports: List[int], interval: int, 
                         log_dir: str = 'logs', **kwargs):
        """Run scheduled scans with logging"""
        os.makedirs(log_dir, exist_ok=True)
        last_result = []
        try:
            while True:
                timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
                open_ports = self.scan_ports(host, ports, **kwargs)
                log_path = os.path.join(log_dir, f"scan_{timestamp}.log")
                ndjson_path = os.path.join(log_dir, f"scan_{timestamp}.ndjson")

                if open_ports != last_result:
                    with open(log_path, 'w') as log:
                        log.write(f"Scan: {timestamp}\n")
                        for port, banner in open_ports:
                            log.write(f"{port}: {banner}\n")

                    self.save_to_ndjson(ndjson_path, host, open_ports)
                    print(f"📦 Saved log: {log_path}")
                    print(f"📄 NDJSON: {ndjson_path}")

                    if kwargs.get("email_cfg"):
                        self.send_email_report(
                            subject="Port changes detected",
                            body=f"New results:\n" + "\n".join(f"{p}: {b}" for p, b in open_ports),
                            **kwargs["email_cfg"]
                        )
                else:
                    print("⏱️  No changes, skipping save.")

                last_result = open_ports
                time.sleep(interval)
        except KeyboardInterrupt:
            print("🛑 Schedule stopped.")

def main():
    """Main command-line interface"""
    parser = argparse.ArgumentParser(description="OmniPort - Advanced Network and Security Scanner")
    parser.add_argument('host', help="Target IP or domain")
    parser.add_argument('-p', '--ports', default='1-1024', help="Port range or 'top' for top 100 ports")
    parser.add_argument('--protocol', choices=['tcp', 'udp'], default='tcp')
    parser.add_argument('--banners', action='store_true', help="Grab service banners")
    parser.add_argument('--rate-limit', type=int, default=0, help="Requests per second limit")
    parser.add_argument('--retry', type=int, default=1, help="Number of retries per port")
    parser.add_argument('--stealth', action='store_true', help="Randomize port order")
    parser.add_argument('--fuzzy', action='store_true', help="Scan ports ±10 from specified")
    parser.add_argument('--check-banner', action='store_true', help="Check for weak banners")
    parser.add_argument('--traceroute', action='store_true', help="Run traceroute")
    parser.add_argument('--endpoints', action='store_true', help="Scan common web endpoints")
    parser.add_argument('--jwt', action='store_true', help="Check for JWT tokens")
    parser.add_argument('--hsts', action='store_true', help="Check HSTS header")
    parser.add_argument('--cve', action='store_true', help="Check for known vulnerabilities")
    parser.add_argument('--firewall-check', action='store_true', help="Check firewall rules")
    parser.add_argument('--honeypot-check', action='store_true', help="Check for honeypots")
    parser.add_argument('--upnp', action='store_true', help="Scan for UPnP devices")
    parser.add_argument('--classify', action='store_true', help="Classify device types")
    parser.add_argument('--ja3', action='store_true', help="Get JA3 TLS fingerprint")
    parser.add_argument('--wordlist-path', help="Path to endpoints wordlist file")
    parser.add_argument('--schedule', type=int, help="Time in seconds between scans")
    parser.add_argument('--log-dir', default='logs', help="Directory for scan logs")
    parser.add_argument('--log-only-changes', action='store_true', help="Only log changes")
    parser.add_argument('--proxy', help="Use proxy (http://... or socks5://...)")
    parser.add_argument('--interface', help="Force network interface (e.g. eth0)")
    parser.add_argument('--netbios', action='store_true', help="Query NetBIOS name")
    parser.add_argument('--whois', action='store_true', help="Get WHOIS information")
    parser.add_argument('--shodan', action='store_true', help="Get Shodan information")
    parser.add_argument('--dns', action='store_true', help="Get DNS records")
    parser.add_argument('--subnet', help="Scan entire subnet (e.g. 192.168.1.0/24)")
    parser.add_argument('--output', choices=['text', 'json', 'csv'], default='text', help="Output format")
    parser.add_argument('--version', action='store_true', help="Show version and exit")

    args = parser.parse_args()
    
    scanner = OmniPortScanner()
    
    if args.version:
        print(f"OmniPort v{scanner.version}")
        return

    if args.interface:
        print("Available interfaces:", scanner.list_interfaces())
        print(f"Using interface: {args.interface} (custom handling required)")

    try:
        ip = scanner.resolve_hostname(args.host)
        if not ip:
            if scanner.is_ipv6(args.host):
                ip = args.host
            else:
                print("Could not resolve hostname.")
                return
    except Exception as e:
        print(f"Error resolving host: {e}")
        return

    ports = scanner.parse_ports_input(args.ports, TOP_100_PORTS)
    if not ports:
        return

    # Flagi do śledzenia znalezionych elementów
    found_weak_banner = False
    found_cve = False
    found_honeypot = False
    found_endpoints = False
    found_jwt = False
    found_upnp = False
    found_classification = False

    if args.netbios:
        print("NetBIOS:", scanner.query_netbios(ip))

    if args.whois:
        print("WHOIS:", scanner.get_whois_info(args.host))

    if args.shodan:
        api_key = os.getenv('SHODAN_API_KEY')
        if not api_key:
            print("Set SHODAN_API_KEY environment variable")
            return
        print("Shodan:", scanner.get_shodan_info(ip, api_key))

    if args.dns:
        print("DNS A records:", scanner.get_dns_records(args.host))

    if args.proxy:
        url = f"http://{ip}:{ports[0]}"
        status, response = scanner.scan_with_proxy(url, args.proxy)
        print(f"Proxy test ({args.proxy}): {status} -> {response[:100]}")

    if args.schedule:
        scanner.run_scheduled_scan(
            ip,
            ports,
            interval=args.schedule,
            log_dir=args.log_dir,
            banner_grab=args.banners,
            retry=args.retry,
            stealth=args.stealth,
            fuzzy=args.fuzzy,
            protocol=args.protocol
        )
        return

    if args.subnet:
        results = scanner.scan_network_subnet(
            args.subnet,
            ports,
            protocol=args.protocol,
            banner_grab=args.banners,
            rate_limit=args.rate_limit,
            retry=args.retry,
            stealth=args.stealth,
            fuzzy=args.fuzzy
        )
    else:
        results = {ip: scanner.scan_ports(
            ip,
            ports,
            protocol=args.protocol,
            banner_grab=args.banners,
            rate_limit=args.rate_limit,
            retry=args.retry,
            stealth=args.stealth,
            fuzzy=args.fuzzy
        )}

    # Process results
    for host, open_ports in results.items():
        print(f"\nResults for {host}:")
        if not open_ports:
            print("ℹ️  No open ports found")
            continue
            
        for port, banner in open_ports:
            print(f"{port}: {banner}")
            if args.check_banner and scanner.is_weak_banner(banner):
                found_weak_banner = True
                print("⚠️  Weak or suspicious banner")
            if args.cve:
                cve = scanner.match_known_cves(banner)
                if cve:
                    found_cve = True
                    print(f"  🛡️  Known vulnerability: {cve}")

    # Dodanie komunikatów "Nie znaleziono"
    if args.check_banner and not found_weak_banner:
        print("ℹ️  No weak banners found")
    
    if args.cve and not found_cve:
        print("ℹ️  No known vulnerabilities found")

    # Endpoints
    if args.endpoints or args.wordlist_path:
        brute = scanner.brute_force_endpoints(args.host, wordlist_path=args.wordlist_path)
        if brute:
            found_endpoints = True
            for path, status in brute:
                print(f"🔎 Endpoint: {path} ({status})")
    
    if (args.endpoints or args.wordlist_path) and not found_endpoints:
        print("ℹ️  No web endpoints found")

    # HSTS
    if args.hsts:
        hsts = scanner.check_hsts(args.host)
        print("HSTS:", "✅" if hsts else "❌")
        if not hsts:
            print("ℹ️  HSTS header not present")

    # JWT
    if args.jwt:
        try:
            html = scanner.session.get(f"http://{args.host}").text
            jwts = scanner.extract_jwt_tokens(html)
            if jwts:
                found_jwt = True
                for j in jwts:
                    print(f"🔐 JWT found: {j}")
        except:
            print("Could not fetch page for JWT scan")
    
    if args.jwt and not found_jwt:
        print("ℹ️  No JWT tokens found")

    # Traceroute
    if args.traceroute:
        print(scanner.run_traceroute(args.host))

    # UPnP
    if args.upnp:
        devices = scanner.detect_upnp_services()
        if devices:
            found_upnp = True
            for addr, desc in devices:
                print(f"UPnP device: {addr}\n{desc}\n")
    
    if args.upnp and not found_upnp:
        print("ℹ️  No UPnP devices found")

    # Device classification
    if args.classify:
        for host in results:
            ttl = scanner.get_ttl(host)
            for port, banner in results[host]:
                classification = scanner.classify_device_type(banner, ttl)
                if classification != "Unknown":
                    found_classification = True
                print(f"🧠 Device ({host}:{port}): {classification}")
    
    if args.classify and not found_classification:
        print("ℹ️  Could not classify any devices")

    # Honeypot detection
    if args.honeypot_check:
        for host in results:
            ttl = scanner.get_ttl(host)
            for port, banner in results[host]:
                is_hp = scanner.detect_honeypot(ttl, banner, 0.5)
                if is_hp:
                    found_honeypot = True
                    print(f"🕵️ Possible honeypot on {host}:{port}")
    
    if args.honeypot_check and not found_honeypot:
        print("ℹ️  No honeypot indicators detected")

    # JA3 fingerprint
    if args.ja3:
        print("JA3 fingerprint:", scanner.get_ja3_hash(args.host))

    # Generate final report
    print("\n" + scanner.generate_report(results, args.output))

if __name__ == '__main__':
    main()