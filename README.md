# 🔥 SSRF-Scanner 🔥
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

# SSRF-Scanner

SSRF(Server-side request forgery) is a trending vulnerability identified in most web applications in which attackers can cause server-side applications to make HTTP requests to arbitrary domains or subdomains. SSRF-Scanner tool is an automated tool that can find the potential SSRF issues actually from a Infrastructure prospective. SSRF-Scanner helps you detect potential SSRF headers and validates the finding it by making a HTTP request back to your server. Actually it support only headers attack but in future versions will also include scanning from an application perspective.

**Installation**

```
git clone https://github.com/Dancas93/SSRF-Scanner.git
cd SSRF-Scanner
pip3 install -r requirements.txt
```

**How To Use**

Print help menu
```python3 ssrf.py -h```

You can choose if analyze a single url or a list of urls, example:
for a single url: ```python3 ssrf.py -u https://google.com```
for a list of url: ```python3 ssrf.py -f urls.txt -c PHPSESSID=123456```

With SSRF-Scanner you can also perform a reverse connection attack, example:
```python3 ssrf.py -u https://google.com -b http://pingb.in/p/bac42078d9061876cbc7ecf2220b```


****Results****

The program will create an output file in csv format in which all responses having response code or response size different from the standard one will be listed. 
Also, if a backurl has been specified with the -b parameter, it is necessary to monitor the url to view any requests received. 
