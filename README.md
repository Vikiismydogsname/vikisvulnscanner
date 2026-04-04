# Vikis Vulnerability Scanner

A lightweight vulnerability and misconfiguration scanner written in Python.

As you could probably guess from the title, the tool is designed to fully automate the initial recconnaisance and vulnerability discovery of an assessment. It identifies open services, grabs banners and checks for common misconfigurations, it also references software versions against known databases.




## Features

- Asynchronous TCP port scanning.
- Banner grabbing and service version detection.
- Automated checks for missing security headers and exposed config files.
- Automatic CVE Lookups on public databases.
- Exporting as JSON, CSV or standard terminal output.




## Installation

Make sure you've got python 3.8+ installed

1. Clone the repo:
```bash
  git clone https://github.com/Vikiismydogsname/vikisvulnscanner.git
  cd vikisvulnscanner
```

2.  Install the required dependencies:

```bash
pip install -r requirements.txt
```

3. Make the scanner executable (For Mac/Linux):
```bash
chmod +x vuln_scanner.py
```
## Usage

### Basic Syntax

```bash
python vuln_scanner.py -t <target> [options]
```

### Quick Start Examples

**1. Basic scan of a single target:**
```bash
python vuln_scanner.py -t example.com
```

**2. Quick scan (top 100 ports + basic checks):**
```bash
python vuln_scanner.py -t 192.168.1.1 --quick
```

**3. Full comprehensive scan:**
```bash
python vuln_scanner.py -t example.com --full-scan -o report.json
```

**4. Web application scan only:**
```bash
python vuln_scanner.py -t https://example.com --web-only
```

**5. Scan multiple targets from a file:**
```bash
python vuln_scanner.py -T targets.txt --threads 20 -o results.json
```

**6. Specific port range:**
```bash
python vuln_scanner.py -t example.com -p 1-1000,3306,5432,8080
```

**7. Generate multiple report formats:**
```bash
python vuln_scanner.py -t example.com --json report.json --csv report.csv --html report.html
```

### Command Line Options

#### Target Selection
```
-t, --target TARGET           Single target (IP or domain)
-T, --target-file FILE        File containing list of targets
```

#### Port Scanning
```
-p, --ports PORTS             Port range (e.g., "80,443" or "1-1000")
--top-ports N                 Scan top N most common ports
--all-ports                   Scan all 65535 ports (slow)
```

#### Scan Presets
```
--quick                       Quick scan (top 100 ports, basic checks)
--full-scan                   Full comprehensive scan (all features)
--web-only                    Web application checks only
```

#### Vulnerability Checks
```
--check-headers               Check security headers
--check-ssl                   Check SSL/TLS configuration
--check-cve                   Query CVE database
--check-files                 Check for exposed sensitive files
--check-cms                   Detect and check CMS platforms
```

#### Performance
```
--threads N                   Number of concurrent threads (default: 10)
--timeout N                   Connection timeout in seconds (default: 5)
--delay N                     Delay between requests in seconds (default: 0)
```

#### Output
```
-o, --output FILE             Output file (.json, .csv, or .txt)
--json FILE                   Export to JSON
--csv FILE                    Export to CSV
--html FILE                   Export to HTML report
-v, --verbose                 Verbose output
--no-color                    Disable colored output
```

## Target File Format

Create a text file with one target per line:

```
# Servers:
192.168.1.1
example.com
www.example.com

# Development:
dev.example.com
```

##  Vulnerability Checks

### Security Headers
Checks for missing or misconfigured headers:
- Strict-Transport-Security (HSTS)
- X-Frame-Options
- Content-Security-Policy
- X-Content-Type-Options
- X-XSS-Protection
- Referrer-Policy
- Permissions-Policy

### SSL/TLS Configuration
- Certificate expiration
- Self-signed certificates
- Deprecated TLS versions (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
- Weak cipher suites

### Exposed Sensitive Files
Scans for publicly accessible files:
- Configuration files (.env, config.php, web.config)
- Version control (.git, .svn)
- Database dumps
- Backup files
- Source code (composer.json, package.json)
- And many more...

### CMS Detection
Identifies and checks:
- WordPress (including XML-RPC and user enumeration)
- Joomla
- Drupal
- Magento

### CVE Database
Queries the National Vulnerability Database (NVD) for known vulnerabilities based on detected software versions.


## License

This tool is provided for educational and authorized security testing purposes only.

##  Contributing

Contributions are welcome! Please ensure any additions:
- Follow the existing code structure
- Include proper error handling
- Add appropriate documentation

have fun! ethically.
