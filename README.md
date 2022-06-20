# SSRF-Scanner

SSRF(Server-side request forgery) is a trending vulnerability identified in most web applications in which attackers can cause server-side applications to make HTTP requests to arbitrary domains or subdomains. SSRF-Scanner tool is an automated tool that can find the potential SSRF issues actually from a Infrastructure prospective. SSRF-Scanner helps you detect potential SSRF headers and validates the finding it by making a HTTP request back to your server. Actually it support only headers attack but in the next release will be implemented also a logic (parameters/form) attack. 

**Installation**

```
git clone https://github.com/Dancas93/SSRF-Scanner.git
cd SSRF-Scanner
pip3 install requirements.txt
```

**How To Use**

Print help menu
`python3 ssrf.py -h`

You can choose if analyze a single url or a list of urls, example:
for a single url: `python3 ssrf.py -u https://google.com`
for a list of url: `python3 ssrf.py -f urls.txt`

With SSRF-Scanner you can also perform a reverse connection attack, example:
`python3 ssrf.py -u https://google.com -b http://pingb.in/p/bac42078d9061876cbc7ecf2220b`

****Todo****
- [ ] refine protocols attack
- [ ] add support to cookie
- [ ] add enclosed parameters attack
- [ ] add application login attack (es. parameters/form)
