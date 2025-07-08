# OmniPort - Advanced Network and Security Scanner

OmniPort is a powerful Python-based tool for network scanning, reconnaissance, and vulnerability analysis. It combines multiple modules into one CLI tool designed for security professionals, pentesters, system administrators, and enthusiasts.

---

## Features

- ⚡ Fast TCP/UDP port scanning with multithreading
- 🔒 Service fingerprinting and banner grabbing
- 📈 CVE detection based on banners
- 🔧 HTTP/HTTPS analysis (HSTS, CORS, JWT, XSS, SQLi)
- 🛡 Honeypot detection via TTL + banner heuristics
- 🌐 WHOIS and DNS lookups
- 📄 Shodan integration
- 🏛 UPnP device detection
- 📊 Network monitoring and logging
- 📊 Scheduled port change monitoring + email alerts
- 👥 Device type classification
- 🛀 JA3 TLS fingerprinting

---

## Requirements

Python 3.7+

### Recommended Setup (virtualenv):
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Installation

1. Clone the repository:
```bash
git clone https://github.com/grodd91/omniport.git
cd omniport
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Make the script executable and move to /bin:
```bash
chmod +x omniport.py
sudo mv omniport.py /usr/local/bin/omniport
```
Now you can run it using:
```bash
omniport --help
```

---

## Usage

### Basic Scan:
```bash
omniport scanme.nmap.org -p top --banners
```

### Scan Subnet:
```bash
omniport 192.168.1.0/24 --subnet --classify --fuzzy
```

### Web Security Scan:
```bash
omniport example.com --hsts --jwt --cve --endpoints
```

### Honeypot Detection:
```bash
omniport target.com --honeypot-check --banners
```

### Monitor Open Ports:
```bash
omniport 192.168.1.1 -p 22,80 --schedule 60 --log-dir logs
```

---

## Command-line Options (Shortened)

- `-p`, `--ports`: Port range or `top`
- `--protocol`: `tcp` or `udp`
- `--banners`: Enable banner grabbing
- `--cve`: Check for known vulnerabilities
- `--hsts`: Detect HTTP Strict Transport Security
- `--jwt`: Extract JWT tokens
- `--honeypot-check`: Detect honeypots via TTL & banners
- `--traceroute`: Run traceroute
- `--whois`, `--dns`, `--shodan`: Information gathering
- `--upnp`: Discover UPnP devices
- `--ja3`: Compute JA3 fingerprint
- `--schedule`: Periodic scanning
- `--output`: `text`, `json`, or `csv`

Run `omniport --help` to see the full list.

---

## Logging and Reports

- Results can be saved in NDJSON or CSV
- Scan changes can trigger email alerts
- Logs stored under `logs/` by default

---

## Legal Disclaimer

OmniPort is intended for **authorized testing and educational purposes only**. Unauthorized scanning of networks or systems you do not own or have explicit permission to test is **illegal**.

---

## License

MIT License

---

## Author

Created by [Grodd91] - feel free to fork, contribute or suggest improvements.
