# 🔥 SSRF-Scanner 🔥
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

# SSRF-Scanner

A comprehensive, high-performance SSRF (Server-Side Request Forgery) vulnerability scanner that tests web applications for potential SSRF issues through multiple attack vectors.

## 🎯 Features

- **10 Attack Phases** - Comprehensive testing methodology
- **~28,300 Requests** - Extensive payload coverage per target
- **377 Unique Payloads** - Across 10 different payload categories
- **Smart Baseline Detection** - Reduces false positives
- **Concurrent Scanning** - Up to 200 concurrent requests
- **Rate Limiting** - Configurable requests per second
- **Multiple Output Formats** - JSON, CSV, HTML, TXT
- **Real-time Progress** - Live request statistics and success rates
- **Async/Await** - High-performance asynchronous implementation

## Installation

### Clone the repository

```
git clone https://github.com/Dancas93/SSRF-Scanner.git
cd SSRF-Scanner
```

### Create virtual environment

```
python3 -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate

# On Windows:
.\venv\Scripts\activate

# Install requirements
pip3 install -r requirements.txt
```

## 🚀 Quick Start

### Basic Usage

```bash
# Scan a single URL
python3 ssrf_scanner.py -u https://example.com

# Scan multiple URLs from file
python3 ssrf_scanner.py -f urls.txt

# Scan with callback URL for remote SSRF detection
python3 ssrf_scanner.py -u https://example.com -b your-callback.burpcollaborator.net

# High-speed scan with custom settings
python3 ssrf_scanner.py -u https://example.com --concurrency 300 --rate-limit 150

# Quiet mode (only show vulnerabilities)
python3 ssrf_scanner.py -u https://example.com -q

# Multiple output formats
python3 ssrf_scanner.py -u https://example.com --output-format html,json,csv
```

### Command Line Options

```
-h, --help              Show help message
-u, --url              Single URL to scan
-f, --file             File containing URLs to scan
-b, --backurl          Callback URL for remote SSRF detection
-d, --debug            Enable debug mode
-c, --cookie           Set cookies (format: 'name1=value1; name2=value2')
--concurrency N        Number of concurrent requests (default: 200)
--rate-limit N         Max requests per second (default: 100)
-q, --quiet            Only show vulnerabilities (no progress)
--proxy URL            Proxy URL (e.g., http://127.0.0.1:8080)
--proxy-auth U:P       Proxy authentication (username:password)
--output-format FMT    Output format: json, csv, html, txt, all (default: csv)
```

## 🎯 Attack Phases

The scanner performs **10 comprehensive attack phases** with **~28,300 total requests**:

### 1. Local IP Attack (20% - ~5,600 requests)
Tests for internal network access using various IP formats:
- **35 base payloads** × 27 headers × variations
- Standard localhost (`127.0.0.1`, `localhost`, `::1`)
- IP encoding (decimal: `2130706433`, hex: `0x7f000001`, octal: `0177.0.0.1`)
- IPv6 variations (`[::1]`, `[0:0:0:0:0:ffff:127.0.0.1]`)
- Unicode variations (`127。0。0。1`)
- URL encoded formats

### 2. Cloud Metadata Attack (12% - ~3,400 requests)
Attempts to access cloud service metadata endpoints:
- **39 payloads** targeting AWS, GCP, Azure, DigitalOcean, Alibaba Cloud
- AWS: `169.254.169.254/latest/meta-data/`
- GCP: `metadata.google.internal/computeMetadata/v1/`
- Azure: `169.254.169.254/metadata/instance`
- IMDSv1 and IMDSv2 variations
- Encoded and obfuscated endpoints

### 3. Protocol Attack (12% - ~3,400 requests)
Tests various protocol handlers:
- **21 protocols** from `protocols.txt`
- Standard: `http://`, `https://`, `ftp://`, `file://`
- Advanced: `gopher://`, `dict://`, `ldap://`, `jar://`
- Database: `mysql://`, `mongodb://`, `postgres://`, `redis://`
- Network: `ws://`, `wss://`, `smtp://`
- Protocol-specific handlers (Gopher commands, Dict queries, File paths)

### 4. Encoded Payload Attack (8% - ~2,300 requests)
Uses encoding techniques to bypass filters:
- **10 base payloads** with multiple encoding variations
- Single/double URL encoding
- Base64 encoding
- Unicode encoding (`。`, `／`)
- Mixed encoding combinations
- Hex encoding

### 5. Parameter Attack (8% - ~2,300 requests)
Tests SSRF through URL parameters:
- **66 parameter payloads**
- Common: `url=`, `path=`, `redirect=`, `uri=`, `file=`
- File inclusion: `document=`, `page=`, `load=`
- API: `callback=`, `webhook=`, `api_url=`
- Redirect: `redirect_to=`, `return_url=`, `next=`

### 6. Port Scan Attack (8% - ~2,300 requests)
Detects internal services via port scanning:
- **33 port payloads**
- Web: `:80`, `:443`, `:8080`, `:8443`
- Database: `:3306`, `:5432`, `:6379`, `:27017`
- Admin: `:8000`, `:8008`, `:9000`
- Services: `:22`, `:21`, `:25`, `:9200`

### 7. DNS Rebinding Attack (8% - ~2,300 requests)
Tests DNS rebinding vulnerabilities:
- **13 payloads** including Burp Collaborator integration
- `127.0.0.1.nip.io`, `127.0.0.1.xip.io`
- `localhost.localtest.me`
- Custom callback domains (with `-b` flag)
- Time-based DNS variations

### 8. CRLF Injection Attack (10% - ~2,800 requests) 🆕
Manipulates HTTP requests via newline injection:
- **43 CRLF payloads**
- Header injection: `%0d%0aHost:%20evil.com`
- Request smuggling: `%0d%0aTransfer-Encoding:%20chunked`
- Response splitting: `%0d%0aHTTP/1.1%20200%20OK`
- Cache poisoning: `%0d%0aX-Forwarded-Scheme:%20http`
- Session fixation: `%0d%0aSet-Cookie:%20admin=true`
- CORS bypass: `%0d%0aAccess-Control-Allow-Origin:%20*`

### 9. Scheme Confusion Attack (10% - ~2,800 requests) 🆕
Tests alternative/rare protocols to bypass filters:
- **90+ scheme payloads**
- Java-specific: `jar:`, `netdoc:`
- PHP wrappers: `php://filter`, `expect://`, `phar://`
- Data URIs: `data://text/plain;base64,`
- File transfer: `tftp://`, `nfs://`, `rsync://`, `smb://`
- Directory: `ldap://`, `ldapi://`
- Version control: `git://`, `svn://`
- Streaming: `rtsp://`, `rtmp://`
- Remote access: `ssh://`, `telnet://`, `rdp://`, `vnc://`
- Compression: `compress.zlib://`, `compress.bzip2://`

### 10. Remote Attack (4% - ~1,100 requests)
External callback validation (requires `-b` flag):
- **10 callback URL variations**
- Plain: `your-callback.com`
- HTTP/HTTPS: `http://your-callback.com`
- With paths: `/ssrf-test`
- With ports: `:80`, `:443`, `:8080`
- URL encoded (single and double)
- Tests external communication and DNS resolution


## 🔍 Verification Methods

The scanner uses **smart baseline comparison** to reduce false positives:

### 1. Response Code Analysis
- Compares against baseline status codes
- Only flags if status code **differs** from baseline
- Excludes rate limiting (429) from vulnerabilities
- Detects unexpected status changes

### 2. Response Content Analysis
- Searches for SSRF indicators:
  - `root:`, `admin:` (user lists)
  - `AWS`, `metadata`, `credentials` (cloud metadata)
  - `BEGIN RSA`, `BEGIN PRIVATE` (private keys)
  - `api_key`, `secret`, `token` (sensitive data)
- Excludes rate limiting responses
- Content fingerprinting

### 3. Response Headers Analysis
- Detects suspicious headers:
  - `x-internal`, `server-internal`
  - `x-backend-server`, `x-upstream`
  - `x-forwarded-server`
- Internal service indicators

### 4. Timing Analysis
- Response time differences
- Timeout-based detection
- Port scanning via timing

### Smart Baseline Detection
- Creates baseline with 3 initial requests
- Tracks status codes, response sizes, content hashes
- Determines response stability
- Only flags **significant deviations** from baseline
- Prevents false positives when status matches baseline

## 📊 Output and Reporting

### Output Formats
The scanner generates multiple report formats:

1. **JSON Report** (`output/report.json`)
   - Machine-readable format
   - Complete vulnerability details
   - Easy integration with other tools

2. **CSV Report** (`output/report.csv`)
   - Spreadsheet-compatible
   - Sortable and filterable
   - Good for data analysis

3. **HTML Report** (`output/report.html`)
   - Visual, interactive report
   - Statistics and charts
   - Color-coded severity
   - Professional presentation

4. **Text Report** (`output/report.txt`)
   - Human-readable format
   - Quick review
   - Terminal-friendly

### Report Contents
Each vulnerability finding includes:
- **Target URL** - The tested endpoint
- **Attack Type** - Phase that detected the issue (e.g., CRLF_Injection, Scheme_Confusion)
- **Payload** - Exact payload that triggered the vulnerability
- **Response Code** - HTTP status code received
- **Response Size** - Size of the response in bytes
- **Verification Method** - How it was verified (e.g., "Response Content Analysis")
- **Timestamp** - When the vulnerability was detected
- **Notes** - Additional details and differences from baseline

### Summary Statistics
- Total URLs scanned
- Total requests made
- Vulnerabilities found
- Success rate (%)
- Unique attack types
- Breakdown by attack phase
- Scan duration

## 📈 Performance

### Speed & Efficiency
- **Concurrent Requests**: Up to 200 simultaneous connections
- **Rate Limiting**: Configurable (default: 100 req/s)
- **Adaptive Throttling**: Automatically adjusts based on errors
- **Smart Backoff**: Reduces rate on failures, increases on success
- **Async/Await**: High-performance asynchronous implementation

### Typical Scan Times
- **Single URL**: ~3-5 minutes (28,300 requests at 100 req/s)
- **With high concurrency**: ~2-3 minutes (300 concurrent, 150 req/s)
- **Multiple URLs**: Scales linearly

### Resource Usage
- **Memory**: ~100-200 MB
- **CPU**: Moderate (async I/O bound)
- **Network**: Configurable bandwidth usage

## 🛡️ Security Features

### Smart Detection
- ✅ Baseline comparison to reduce false positives
- ✅ Rate limiting exclusion (429 not flagged as vulnerability)
- ✅ Response pattern analysis
- ✅ Content-based verification
- ✅ Timing-based detection

### Safe Scanning
- ✅ Configurable rate limiting
- ✅ Timeout handling
- ✅ Error recovery
- ✅ Graceful degradation
- ✅ Connection pooling

## 📦 Payload Files

All payloads are stored in the `payloads/` directory:

```
payloads/
├── local_ips.txt           (35 payloads)   - Internal IP variations
├── headers.txt             (27 payloads)   - HTTP headers to test
├── cloud_metadata.txt      (39 payloads)   - Cloud metadata endpoints
├── protocols.txt           (21 payloads)   - Protocol handlers
├── encoded_payloads.txt    (10 payloads)   - Encoding variations
├── parameter_payloads.txt  (66 payloads)   - URL parameters
├── port_payloads.txt       (33 payloads)   - Port specifications
├── dns_rebinding.txt       (13 payloads)   - DNS rebinding domains
├── crlf_injection.txt      (43 payloads)   - CRLF injection patterns
└── scheme_confusion.txt    (90 payloads)   - Alternative protocols
```

**Total: 377 unique payloads**

You can customize any payload file to add your own test cases!

## 🎯 Example Output

```
░██████╗░██████╗██████╗░███████╗
██╔════╝██╔════╝██╔══██╗██╔════╝
╚█████╗░╚█████╗░██████╔╝█████╗░░
░╚═══██╗░╚═══██╗██╔══██╗██╔══╝░░
██████╔╝██████╔╝██║░░██║██║░░░░░
╚═════╝░╚═════╝░╚═╝░░╚═╝╚═╝

[*] Configuration:
    Concurrency: 200
    Rate Limit: 100 req/s
    Timeout: 15s
    Output Format: json

[*] Creating baseline for https://example.com...
[*] Baseline: Status={200}, AvgSize=3125, Stable=Yes
[*] Starting attack phases...

URLs: 1/1 | Requests: 5,234/28,300 (98.5% success, 112.3 req/s) | Phase: Local IP | Progress: 20.0%
URLs: 1/1 | Requests: 18,234/28,300 (99.1% success, 118.4 req/s) | Phase: CRLF Injection | Progress: 64.0%
URLs: 1/1 | Requests: 28,300/28,300 (99.5% success, 121.5 req/s) | Phase: Remote | Progress: 100.0%

⏱️  Total Scan Time: 233.12 seconds

==================================================
SSRF Scan Summary
==================================================
Statistics:
--------------------
Total URLs Scanned: 1
Total Requests: 28,300
Vulnerabilities Found: 3
Success Rate: 99.5%
Unique Attack Types: 2

Vulnerabilities by Attack Type:
------------------------------
CRLF_Injection: 2 found
Scheme_Confusion: 1 found
==================================================
Detailed results saved in:
JSON Report: output/report.json
```

## 🤝 Contributing

Contributions are welcome! Feel free to:
- Add new payload files
- Improve detection methods
- Optimize performance
- Fix bugs
- Enhance documentation

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is for educational and authorized security testing purposes only. Users are responsible for ensuring they have permission to test target systems. The developers assume no liability for misuse or damage caused by this tool.
