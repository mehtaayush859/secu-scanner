# SecuScan

**SecuScan** is a modular, cross-platform vulnerability and misconfiguration scanner for local systems and web applications.  
It helps you identify open ports, missing security headers, weak passwords, outdated software, and insecure configurations using industry best practices (OWASP, CIS, NVD).

---

## 🚀 Features

- **Port Scanning:** Advanced port scanning with nmap, including scan profiles and risk scoring
- **CVE Detection:** Checks installed software against the latest NVD CVE feeds with CVSS scoring
- **Web Header Scan:** Analyzes HTTP(S) headers for OWASP Top 10 compliance with SSL/TLS analysis
- **Password Audit:** Flags weak, default, or empty passwords (Linux only)
- **Config Audit:** Checks SSH and other configs against secure baselines (Linux only)
- **Network Discovery:** Advanced network host and service enumeration with security analysis
- **Web Application:** Modern React frontend with FastAPI backend for easy scanning
- **Reporting:** Generates reports in JSON, HTML (with template), and PDF (optional)
- **Unit Tests:** Comprehensive test suite for all modules
- **Docker Support:** Ready for containerized deployment

---

## 📦 Requirements

- **Python 3.8+**
- **Node.js 18+** (for frontend)
- **pip** (Python package manager)
- **npm** (Node.js package manager)
- **nmap** (for port scanning)
- **Npcap** (for nmap on Windows)
- **NVD CVE Feed** (JSON, see below)
- **(Optional) WeasyPrint** for PDF reports

---

## 🛠️ Installation

### Option 1: Docker Deployment (Recommended)

1. **Clone the repository:**
   ```sh
   git clone https://github.com/yourusername/SecuScan.git
   cd SecuScan
   ```

2. **Make deployment script executable and run:**
   ```sh
   chmod +x deploy.sh
   ./deploy.sh
   ```

3. **Access the application:**
   - Web Interface: http://localhost:8000
   - API Documentation: http://localhost:8000/docs

### Option 2: Manual Installation

1. **Clone the repository:**
   ```sh
   git clone https://github.com/yourusername/SecuScan.git
   cd SecuScan
   ```

2. **Install Python dependencies:**
   ```sh
   pip install -r requirements.txt
   pip install -r web_app/backend/requirements.txt
   ```

3. **Install frontend dependencies:**
   ```sh
   cd web_app/frontend
   npm install
   npm run build
   cd ../..
   ```

4. **Install nmap:**
   - **Windows:** [Download nmap](https://nmap.org/download.html) and install.  
     During Npcap setup, check:
     - Restrict Npcap driver's access to Administrators only
     - Install Npcap in WinPcap API-compatible Mode
   - **Linux:**  
     ```sh
     sudo apt-get install nmap
     ```

5. **Download the NVD CVE Feed:**
   - Go to [NVD Data Feeds](https://nvd.nist.gov/vuln/data-feeds#JSON_FEED)
   - Download `nvd_recent.json.gz` (recent CVEs) or `nvd.json.gz` (all CVEs)
   - Extract and rename to `cve_cache.json`
   - Place in the `data/` directory:
     ```
     SecuAuth/data/cve_cache.json
     ```

6. **(Optional) For PDF reports:**
   ```sh
   pip install weasyprint
   ```

---

## 📁 Directory Structure

```
SecuScan/
│   main.py                 # CLI entry point
│   requirements.txt        # Python dependencies
│   Dockerfile             # Docker configuration
│   docker-compose.yml     # Docker Compose setup
│   deploy.sh              # Deployment script
│
├── cli_tool/              # Core scanning modules
│     ports.py             # Port scanning with profiles
│     cve_check.py         # CVE detection with NVD API
│     web_scan.py          # Web header and SSL analysis
│     password_audit.py    # Password security audit
│     config_audit.py      # Configuration audit
│     network_discovery.py # Network host/service discovery
│     scanner.py           # Main scanner coordinator
│
├── web_app/               # Web application
│     backend/             # FastAPI backend
│     │   main.py          # API endpoints
│     │   requirements.txt # Backend dependencies
│     │   test_backend.py  # Backend tests
│     │
│     frontend/            # React frontend
│         src/
│         │   App.tsx      # Main application
│         │   components/  # React components
│         │   theme.ts     # Material-UI theme
│
├── reports/               # Reporting system
│     reporter.py          # Report generation
│     templates/           # HTML templates
│     html/                # Generated reports
│
├── data/                  # Data files
│     cve_cache.json       # NVD CVE database
│
├── tests/                 # Test suite
│     test_ports.py        # Port scan tests
│     test_cve_check.py    # CVE check tests
│     test_web_scan.py     # Web scan tests
│     test_password_audit.py
│     test_config_audit.py
│     test_network_discovery.py
```

---

## ⚡ Usage

### **Web Application (Recommended)**

1. **Start the application:**
   ```sh
   # Using Docker
   ./deploy.sh
   
   # Or manually
   cd web_app/backend
   python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
   ```

2. **Open your browser:**
   - Navigate to http://localhost:8000
   - Use the modern web interface for scanning

### **Command Line Interface**

```sh
# Basic scan
python main.py --target 127.0.0.1 --scan-type full --output json

# Advanced scan with profile
python main.py --target 127.0.0.1 --scan-type ports --scan-profile aggressive --output html

# Network discovery
python main.py --target 192.168.1.0/24 --scan-type network --output json

# Web security scan
python main.py --target https://example.com --scan-type web --output html
```

### **Scan Types**

- `full`      : All scans (ports, cve, web, password, config, network)
- `ports`     : Advanced port scan with profiles
- `cve`       : CVE check with NVD API support
- `web`       : Web header and SSL/TLS analysis
- `password`  : Password audit (Linux only)
- `config`    : Config baseline audit (Linux only)
- `network`   : Network host and service discovery

### **Scan Profiles**

- `default`     : Standard scan (balanced speed/accuracy)
- `stealth`     : Slow, quiet scan
- `aggressive`  : Fast, comprehensive scan
- `vuln`        : Vulnerability-focused scan

### **Output Formats**

- `json` : Machine-readable JSON report
- `html` : Human-friendly HTML report (see `reports/html/scan_report.html`)
- `pdf`  : PDF report (requires WeasyPrint, experimental)

### **Run All Unit Tests**

```sh
python main.py --run-tests
# Or
python -m pytest tests/
```

---

## 🐳 Docker Deployment

### **Quick Start**
```sh
./deploy.sh
```

### **Manual Docker Commands**
```sh
# Build and start
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down

# Rebuild and restart
docker-compose up -d --build
```

### **Production Deployment**
```sh
# Build production image
docker build -t secuscan:latest .

# Run with custom configuration
docker run -d \
  -p 8000:8000 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/reports:/app/reports \
  --name secuscan \
  secuscan:latest
```

---

## 📝 Report Template

- HTML reports use a Jinja2 template at `reports/templates/report_template.html`.
- You can customize this template for your organization's branding or reporting needs.

---

## 🛡️ Permissions & Platform Notes

- **Port scan**: May require admin on Windows (Npcap).
- **Password/config audit**: Linux only, requires root for full results.
- **CVE check**: Works on both Windows and Linux, but software extraction is more robust on Linux.
- **Web scan**: Works on any platform, but target must be reachable.
- **Network discovery**: Linux only for ARP scanning, ping/nmap work on all platforms.

---

## 🧪 Testing

- All modules have comprehensive unit tests in the `tests/` directory.
- Run all tests with:
  ```sh
  python main.py --run-tests
  ```
- Or run a specific test:
  ```sh
  python -m pytest tests/test_ports.py
  ```

---

## 🛠️ Troubleshooting

- **nmap not found**: Ensure nmap is installed and in your PATH.
- **Npcap errors**: Run terminal as Administrator on Windows.
- **No CVEs detected**: Make sure `data/cve_cache.json` is present and up to date.
- **Permission denied**: For password/config audits, run as root (Linux) or Administrator (Windows).
- **Web scan connection refused**: Make sure the target URL is up and reachable.
- **Docker build fails**: Ensure Docker and Docker Compose are properly installed.

---

## 📚 Contributing

Pull requests, bug reports, and feature suggestions are welcome!  
Please open an issue or PR on GitHub.

---

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.

---

## 🙋 FAQ

**Q: Can I scan remote systems for CVEs?**  
A: Currently, CVE checks are local only. Remote support may be added in the future.

**Q: Is the web application secure for production use?**  
A: The application is designed for internal/development use. For production deployment, consider adding authentication, HTTPS, and proper security measures.

**Q: Can I customize the scan profiles?**  
A: Yes, you can modify the scan profiles in the respective modules or create custom profiles.

**Q: How do I update the CVE database?**  
A: Download the latest NVD feed and replace `data/cve_cache.json`, or use the deployment script which handles this automatically.

---

**SecuScan** – Security made simple and modular.