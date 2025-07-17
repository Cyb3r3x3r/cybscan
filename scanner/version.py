# scanner/version.py

import re
import logging
import requests
from bs4 import BeautifulSoup
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from scanner.assets import check_wp_core_vulnerabilities
from scanner.colors import CYAN,RED,YELLOW,RESET,GREEN

log = logging.getLogger("CybScan")

def current_wp_version():
    """Get the latest WordPress version from official site"""
    try:
        res = requests.get("https://wordpress.org/download/", timeout=10, verify=False)
        match = re.search(r"Download WordPress ([0-9.]+)", res.text)
        if match:
            log.info(f"{CYAN}[WP] Latest WordPress Version: {match.group(1)}{RESET}")
            version = match.group(1)
            check_wp_core_vulnerabilities(version)
    except Exception as e:
        log.warning(f"{RED}Failed to fetch current WP version: {e}{RESET}")

def from_meta_generator(base_url, session):
    try:
        html = session.get(base_url).text
        match = re.search(r'WordPress ([0-9.]+)', html)
        if match:
            log.info(f"{GREEN}[WP] Version from meta tag: {match.group(1)}{RESET}")
            version = match.group(1)
            check_wp_core_vulnerabilities(version)
            return True
    except Exception:
        pass
    return False

def from_readme(base_url, session):
    try:
        html = session.get(f"{base_url}/readme.html").text
        match = re.search(r'Version ([0-9.]+)', html)
        if match:
            log.info(f"{GREEN}[WP] Version from readme.html: {match.group(1)}{RESET}")
            version = match.group(1)
            check_wp_core_vulnerabilities(version)
            return True
    except Exception:
        pass
    return False

def from_html_source(base_url, session):
    try:
        html = session.get(base_url).text
        matches = re.findall(r"ver=([0-9.]+)", html)
        if matches:
            log.info(f"{GREEN}[WP] Version from HTML assets: {matches[0]}{RESET}")
            version = matches[0]
            check_wp_core_vulnerabilities(version)
            return True
    except Exception:
        pass
    return False

def from_rss_feed(base_url, session):
    try:
        html = session.get(f"{base_url}/feed/").text
        match = re.search(r"wordpress\.org/\?v=([0-9.]+)", html)
        if match:
            log.info(f"{GREEN}[WP] Version from RSS feed: {match.group(1)}{RESET}")
            version = match.group(1)
            check_wp_core_vulnerabilities(version)
            return True
    except Exception:
        pass
    return False

def detect_wp_version(base_url, session):
    log.info(f"{YELLOW}Detecting WordPress Version...{RESET}")
    current_wp_version()

    if from_readme(base_url, session): return
    if from_meta_generator(base_url, session): return
    if from_html_source(base_url, session): return
    if from_rss_feed(base_url, session): return

    log.warning(f"{RED}[WP] WordPress version could not be determined.{RESET}")
