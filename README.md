# 🔥 SSRF-Scanner 🔥
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

# SSRF-Scanner

SSRF(Server-side request forgery) is a trending vulnerability identified in most web applications in which attackers can cause server-side applications to make HTTP requests to arbitrary domains or subdomains. SSRF-Scanner tool is an automated tool that can find the potential SSRF issues actually from a Infrastructure prospective. SSRF-Scanner helps you detect potential SSRF headers and validates the finding it by making a HTTP request back to your server. Actually it support only headers attack but in future versions will also include scanning from an application perspective.

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

## How To Use

Print help menu
```python3 ssrf_scanner.py -h```

You can choose if analyze a single url or a list of urls, example:
for a single url: ```python3 ssrf.py -u https://google.com```
for a list of url: ```python3 ssrf.py -f urls.txt```

With SSRF-Scanner you can also perform a reverse connection attack, example:
```python3 ssrf.py -u https://google.com -b http://pingb.in/p/bac42078d9061876cbc7ecf2220b```

## Attack Types

### 1. Local IP Attack
Tests for internal network access using various IP formats and localhost references.
- Standard localhost variations (`127.0.0.1`, `localhost`)
- IP encoding variations (decimal, hexadecimal, octal)
- Alternative notations (`0177.0.0.1`, 2130706433, `0x7f000001`)
- IPv6 variations (`::1`, [::1], `[0:0:0:0:0:ffff:127.0.0.1]`)
- Dotted decimal variations
- Mixed encoding formats

### 2. Cloud Metadata Attack
Attempts to access cloud service metadata endpoints:
- AWS metadata endpoints (`169.254.169.254`)
- Google Cloud metadata
- Azure metadata service
- Digital Ocean metadata
- Alibaba Cloud metadata
Target endpoints include:
- /latest/meta-data/
- /computeMetadata/v1/
- /metadata/instance

### 3. Protocol Attack
Tests various protocol handlers and URL schemes:
- Basic protocols (`http://`, `https://`)
- File protocol (`file://`)
- Gopher protocol (`gopher://`)
- Dict protocol (`dict://`)
- LDAP/LDAPS (`ldap://`, `ldaps://`)
- FTP/SFTP (`ftp://`, `sftp://`)
- Network protocols (`ws://`, `wss://`)
- Database protocols (`mysql://`, mongodb://, postgres://, `redis://`)

### 4. Encoded Payload Attack
Uses different encoding techniques to bypass filters:
- URL encoding
- Double URL encoding
- Base64 encoding
- Unicode encoding
- Mixed encoding combinations
- HTML encoding
- Hex encoding variations

### 5. Parameter Attack
Tests SSRF through URL parameters:
- Common parameter names (`url`, path, redirect, uri, `file`)
- File inclusion parameters (`document`, page, filename, `load`)
- Redirect parameters (`redirect_to`, return_url, `next`)
- API-related parameters (`callback`, webhook, `api_url`)
- Custom parameter variations

### 6. Port Scan Attack
Attempts to detect internal services:
- Common service ports (80, 443, 8080, 8443)
- Database ports (3306, 5432, 6379)
- Admin ports (8000, 8008, 9000)
- Alternative HTTP ports (8080, 8888)
- Custom port specifications
- Port bypass techniques

### 7. DNS Rebinding Attack
Tests for DNS rebinding vulnerabilities:
- Domain-based payloads
- Burp Collaborator integration
- Custom DNS providers (nip.io, xip.io)
- Time-based DNS variations
- Multiple IP resolutions

### 8. Remote Attack (with Callback)
When a callback URL is provided:
- Tests for external communication
- Validates SSRF through DNS requests
- Monitors for delayed callbacks
- Tests different callback formats
- Verifies payload execution

### 9. Headers Attack

The scanner tests SSRF vulnerabilities through various HTTP headers


## Verification Methods
### Response AnalysisThe scanner verifies potential SSRF through:
1. Status code comparison2. Response size differences
2. Content type changes4. Response time variations
3. Error message analysis
### Vulnerability ConfirmationVulnerabilities are confirmed by:
- Response pattern analysis- Content fingerprinting
- Error message signatures- Timing analysis
- Response code patterns

## Output and Reporting
### Results FormatThe scanner generates three types of reports:
1. Text Report: Human-readable findings2. CSV Report: Spreadsheet-compatible format
2. JSON Report: Machine-readable format
### Report ContentsEach finding includes:
- Target URL- Attack Type
- Payload Used- Response Code
- Response Size- Verification Method
- Timestamp- Additional Notes
