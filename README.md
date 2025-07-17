# Cybscan v1.1.6
> ⚡ Updated and expanded in July 2025 with major features!
- Scannner for wordpress websites - 
Many more features will be added further
## Changelog

### v1.1.6
- Major refactor and feature expansion
- Added multithreading support (`--thread`)
- Improved plugin/theme detection with version parsing
- Integrated WPVulnDB API for real vulnerability checks
- Added `--enumerate-users`  flag to optionally enumerate WordPress usernames
- Honeypot detection (reverse DNS, WHOIS, probe)
- Multithreaded internal crawler with `--save-links` support
- Admin panel exposure detection with custom wordlist support (`--admin-wordlist`)
- Brute-force protection detection
- Colored terminal output for better UX
- More reliable link crawler with threading support
- Support for MU-Plugins with `--include-mu` flag


## Installation
Clone or download this repository
```
git clone https://github.com/cyb3r3x3r/cybscan.git
```
Now go to the directory and give permission by 
```
cd cybscan
chmod +x cybscan.py
```
Now install all the required modules from requirements.txt file by 
```
pip install -r requirements.txt
```
and then run
```
python cybscan.py
```
## Features
1. Grab the IP and server info.
2. Detect WordPress version using 5 different methods and check for core vulnerabilities.
3. Grab HTTP headers and highlight security misconfigurations.
4. Check for RSS and comment feed availability.
5. Check if directory indexing is enabled on /wp-content/uploads/.
6. Check if XML-RPC interface is available.
7. Detect installed themes (including from WordPress CDN) and check for vulnerabilities via WPVulnDB API.
8. Detect plugins and mu-plugins (optional flag) with version parsing and vulnerability check.
9. Honeypot detection via reverse DNS, WHOIS, and response analysis.
10. Crawl the website and optionally save all discovered internal links (`--save-links`).
11. Enumerate usernames using REST API, author ID enumeration, and HTML metadata.
12. Brute-force protection detection (basic response analysis to repeated login attempts).
13. Admin panel exposure detection using common and custom wordlists (`--admin-wordlist`).
14. Colorized terminal output for improved readability.
15. Threaded scanning support (`--thread`) for faster operations.

### Usage
```
python cybscan.py example.com
```

***Contact me or help me improving this repository...Thanks***
