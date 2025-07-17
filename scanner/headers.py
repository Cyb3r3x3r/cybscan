# scanner/headers.py

import requests
import logging
import re
from bs4 import BeautifulSoup
from scanner.colors import RED, GREEN, YELLOW, RESET

log = logging.getLogger("CybScan")

def check_http_headers(domain):
    """Fetch HTTP headers from HackerTarget API"""
    try:
        log.info(f"{YELLOW}Fetching HTTP headers...{RESET}")
        url = f"http://api.hackertarget.com/httpheaders/?q={domain}"
        res = requests.get(url, timeout=10)
        if res.status_code == 200:
            log.info(f"{YELLOW}[Headers] HTTP Headers:\n{res.text}{RESET}")
        else:
            log.warning(f"{RED}Could not retrieve headers.{RESET}")
    except Exception as e:
        log.warning(f"{RED}[Headers] Failed to fetch: {e}{RESET}")

def check_rss_feeds(base_url, session):
    """Check if RSS and comment feeds exist and extract info"""
    log.info(f"{YELLOW}[RSS]{RESET} Checking RSS feeds...")
    
    for endpoint in ["/feed/", "/comments/feed/"]:
        try:
            full_url = base_url + endpoint
            res = session.get(full_url, timeout=5)
            if res.status_code == 200:
                soup = BeautifulSoup(res.text, "lxml-xml")  # use XML-aware parser
                match = soup.find("atom:link")
                if match and match.get("href"):
                    log.info(f"{GREEN}[RSS]{RESET} ✅ Feed available: {match['href']}")
                else:
                    log.info(f"{GREEN}[RSS]{RESET} ✅ Feed exists at {full_url} (no <atom:link> found)")
            else:
                log.info(f"{YELLOW}[RSS]{RESET} {endpoint} not found (status: {res.status_code})")
        except Exception as e:
            log.warning(f"{RED}[RSS]{RESET} ⚠ Failed to check {endpoint}: {e}")

def check_directory_indexing(base_url, session):
    """Check if /wp-content/uploads/ allows directory listing"""
    try:
        url = base_url + "/wp-content/uploads/"
        res = session.get(url, timeout=5)

        if "Index of /wp-content/uploads" in res.text or "<title>Index of" in res.text:
            log.warning(f"{YELLOW}[Indexing]{RESET} {RED}⚠ Directory indexing is ENABLED at /wp-content/uploads/{RESET}")
        else:
            log.info(f"{GREEN}[Indexing]{RESET} ✅ Directory indexing is disabled.")
    except Exception as e:
        log.warning(f"{YELLOW}[Indexing]{RESET} {RED}Error while checking directory indexing: {e}{RESET}")

def check_xmlrpc(base_url, session):
    """Check if XML-RPC endpoint exists"""
    try:
        url = base_url + "/xmlrpc.php"
        res = session.get(url, timeout=5)
        if res.status_code == 405:
            log.warning(f"{RED}[-][XML-RPC] Interface is AVAILABLE at /xmlrpc.php (status 405){RESET}")
        elif res.status_code == 200:
            log.warning(f"{RED}[-][XML-RPC] Interface is AVAILABLE at /xmlrpc.php (status 200){RESET}")
        else:
            log.info(f"{YELLOW}[!][XML-RPC] Interface not available.{RESET}")
    except Exception:
        log.warning(f"{RED}[-][XML-RPC] Error checking XML-RPC.{RESET}")
