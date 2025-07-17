# scanner/assets.py

from concurrent.futures import ThreadPoolExecutor, as_completed
from scanner.colors import RED, GREEN, CYAN, YELLOW, RESET
import re
import logging
from urllib.parse import urlparse
import requests
import os
from urllib.parse import urljoin
from dotenv import load_dotenv
load_dotenv()

log = logging.getLogger("CybScan")
WPVULNDB_API = "https://wpscan.com/api/v3"
WPVULNDB_TOKEN = os.getenv("WPVULNDB_TOKEN")

def check_wpvulndb(asset_type, name, version=None):
    """
    Queries the WPVulnDB API to check if a theme/plugin has known vulnerabilities.
    asset_type: 'plugins' or 'themes'
    """
    if not WPVULNDB_TOKEN:
        log.warning(f"{YELLOW}[{asset_type.capitalize()}]{RESET} No WPVulnDB API token found. Skipping real vulnerability check.")
        return

    endpoint = f"{WPVULNDB_API}/{asset_type}/{name.lower()}"
    headers = {"Authorization": f"Token token={WPVULNDB_TOKEN}"}

    try:
        res = requests.get(endpoint, headers=headers, timeout=10)
        if res.status_code == 404:
            log.info(f"{CYAN}[{asset_type.capitalize()}]{RESET} No known vulnerabilities for {GREEN}{name}{RESET}.")
            return

        data = res.json()
        vulns = data.get("vulnerabilities", [])

        if not vulns:
            log.info(f"{CYAN}[{asset_type.capitalize()}]{RESET} No known vulnerabilities for {GREEN}{name}{RESET}.")
            return

        if version:
            # Filter by affected versions
            vulnerable = False
            for v in vulns:
                if "fixed_in" in v:
                    continue  # Skip fixed ones
                vulnerable = True
                log.warning(f"{RED}[{asset_type.capitalize()}]{RESET} ⚠ {YELLOW}{name} v{version}{RESET} is vulnerable: {v.get('title')}")
        else:
            log.warning(f"{RED}[{asset_type.capitalize()}]{RESET} ⚠ {YELLOW}{name}{RESET} has known vulnerabilities!")

    except Exception as e:
        log.warning(f"{RED}[{asset_type.capitalize()}]{RESET} WPVulnDB check failed: {e}")

def check_asset_vulnerability(name, asset_type):
    """
    Check vulnerabilities using WPVulnDB if available.
    Supports name with or without version.
    """
    name_parts = name.lower().split()
    base_name = name_parts[0]
    version = name_parts[1] if len(name_parts) > 1 else None

    check_wpvulndb("plugins" if asset_type == "plugin" else "themes", base_name, version)
def extract_theme_from_url(url: str) -> str:
    """
    Extracts the actual theme name from a given stylesheet/script URL.
    Ignores short, invalid, or known-false names.
    """
    path = urlparse(url).path
    match = re.search(r'/wp-content/themes/(?:pub/)?([^/]+)/', path)
    if match:
        theme = match.group(1)
        # Ignore short/common false names
        if theme.lower() in {"h1", "h2", "h3", "h4", "global", "default", "admin", "mu-plugins"}:
            return None
        if len(theme) <= 2:
            return None
        return theme
    return None


def check_wp_core_vulnerabilities(version):
    """
    Query WPVulnDB API for WordPress core vulnerabilities.
    """
    try:
        token = os.getenv("WPVULNDB_TOKEN")
        if not token:
            log.warning(f"{YELLOW}[Core]{RESET} WPVULNDB_TOKEN is not set.")
            return

        endpoint = f"{WPVULNDB_API}/wordpresses/{version}"
        headers = {"Authorization": f"Token token={token}"}

        res = requests.get(endpoint, headers=headers, timeout=10)
        if res.status_code == 404:
            log.info(f"{CYAN}[Core]{RESET} No known vulnerabilities for WordPress {GREEN}{version}{RESET}")
            return

        data = res.json()
        vulns = data.get("vulnerabilities", [])

        if not vulns:
            log.info(f"{CYAN}[Core]{RESET} WordPress {GREEN}{version}{RESET} has no known vulnerabilities.")
            return

        log.warning(f"{RED}[Core]{RESET} ⚠ WordPress {YELLOW}{version}{RESET} has {RED}{len(vulns)}{RESET} known vulnerabilities:")
        for vuln in vulns:
            title = vuln.get("title", "Unnamed vulnerability")
            references = vuln.get("references", {}).get("url", [])
            log.warning(f"{RED}  - {RESET}{title}")
            if references:
                log.warning(f"{CYAN}    ➤ {RESET}{references[0]}")

    except Exception as e:
        log.warning(f"{RED}[Core]{RESET} WP core vulnerability check failed: {e}")

def detect_theme(base_url, session, thread_count=1):
    """Detect WordPress themes and their versions from the page source."""
    try:
        log.info(f"{CYAN}[Theme]{RESET} Detecting theme(s)...")
        html = session.get(base_url, timeout=5).text

        urls = re.findall(r'https?://[^"]+/wp-content/themes/(?:pub/)?[^/]+/[^"]+', html)

        theme_urls = {}
        for url in urls:
            theme = extract_theme_from_url(url)
            if theme:
                if theme not in theme_urls:
                    theme_urls[theme] = []
                theme_urls[theme].append(url)

        if not theme_urls:
            log.warning(f"{YELLOW}[Theme]{RESET} No themes detected.")
            return

        def process_theme(theme, urls):
            version = None
            for url in urls:
                # Type 1: ?ver=1.2.3
                ver_q = re.search(r'ver=([0-9.]+)', url)
                if ver_q:
                    version = ver_q.group(1)
                    break

                # Type 2: /v1.2.3/
                ver_v = re.search(r'/v([0-9.]+)/', url)
                if ver_v:
                    version = ver_v.group(1)
                    break

            if version:
                log.info(f"{GREEN}[Theme]{RESET} Detected: {CYAN}{theme}{RESET} (v{YELLOW}{version}{RESET})")
                check_asset_vulnerability(f"{theme} {version}", "theme")
            else:
                log.info(f"{GREEN}[Theme]{RESET} Detected: {CYAN}{theme}{RESET}")
                check_asset_vulnerability(theme, "theme")

        if thread_count > 1:
            with ThreadPoolExecutor(max_workers=thread_count) as executor:
                futures = [
                    executor.submit(process_theme, theme, urls)
                    for theme, urls in theme_urls.items()
                ]
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        log.warning(f"{RED}[Theme]{RESET} Error in threaded detection: {e}")
        else:
            for theme, urls in theme_urls.items():
                process_theme(theme, urls)

    except Exception as e:
        log.warning(f"{RED}[Theme]{RESET} Error detecting themes: {e}")

def detect_plugins(base_url, session, include_mu=False, thread_count=1):
    """Detect WordPress plugins (and mu-plugins if allowed) and their versions"""
    try:
        log.info(f"{CYAN}[Plugin]{RESET} Detecting plugin(s)...")
        html = session.get(base_url, timeout=5).text

        urls = re.findall(r'https?://[^"]+/wp-content/(?:mu-plugins|plugins)/[^/]+/[^"]+', html)

        plugin_urls = {}
        for url in urls:
            # Skip mu-plugins unless explicitly included
            if "mu-plugins" in url.lower() and not include_mu:
                continue

            match = re.search(r'/wp-content/(?:mu-plugins|plugins)/([^/]+)/', url)
            if not match:
                continue

            plugin = match.group(1)
            if plugin not in plugin_urls:
                plugin_urls[plugin] = []
            plugin_urls[plugin].append(url)

        if not plugin_urls:
            log.warning(f"{YELLOW}[Plugin]{RESET} No plugins found.")
            return

        def process_plugin(plugin, urls):
            version = None
            for url in urls:
                # ?ver=1.2.3
                ver_q = re.search(r'ver=([0-9.]+)', url)
                if ver_q:
                    version = ver_q.group(1)
                    break

                # /v1.2.3/
                ver_v = re.search(r'/v([0-9.]+)/', url)
                if ver_v:
                    version = ver_v.group(1)
                    break

            if version:
                log.info(f"{GREEN}[Plugin]{RESET} Detected: {CYAN}{plugin}{RESET} (v{YELLOW}{version}{RESET})")
                check_asset_vulnerability(f"{plugin} {version}", "plugin")
            else:
                log.info(f"{GREEN}[Plugin]{RESET} Detected: {CYAN}{plugin}{RESET}")
                check_asset_vulnerability(plugin, "plugin")

        if thread_count > 1:
            with ThreadPoolExecutor(max_workers=thread_count) as executor:
                futures = [
                    executor.submit(process_plugin, plugin, urls)
                    for plugin, urls in plugin_urls.items()
                ]
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        log.warning(f"{RED}[Plugin]{RESET} Error in threaded detection: {e}")
        else:
            for plugin, urls in plugin_urls.items():
                process_plugin(plugin, urls)

    except Exception as e:
        log.warning(f"{RED}[Plugin]{RESET} Error detecting plugins: {e}")



def enumerate_wp_users(base_url, session, max_users=10, thread_count=1):
    """
    Attempts to enumerate WordPress users via:
    1. REST API
    2. /?author=1 to N (threaded if requested)
    3. Parsing /author/ from post metadata
    """
    found_users = set()
    log.info(f"{CYAN}[Users]{RESET} Enumerating WordPress usernames...")

    # --- Method 1: REST API ---
    try:
        rest_url = urljoin(base_url, "/wp-json/wp/v2/users")
        res = session.get(rest_url, timeout=5)
        if res.status_code == 200 and res.headers.get("Content-Type", "").startswith("application/json"):
            for user in res.json():
                username = user.get("slug")
                if username:
                    found_users.add(username)
                    log.warning(f"{YELLOW}[Users]{RESET} Found user via REST API: {GREEN}{username}{RESET}")
    except Exception as e:
        log.warning(f"{RED}[Users]{RESET} REST API check failed: {e}")

    # --- Method 2: /?author=X redirects ---
    def check_author(i):
        try:
            res = session.get(f"{base_url}/?author={i}", allow_redirects=True, timeout=5)
            match = re.search(r'/author/([^/]+)/', res.url)
            if match:
                return match.group(1)
        except Exception:
            pass
        return None

    if thread_count > 1:
        with ThreadPoolExecutor(max_workers=thread_count) as executor:
            futures = {executor.submit(check_author, i): i for i in range(1, max_users + 1)}
            for future in as_completed(futures):
                username = future.result()
                if username and username not in found_users:
                    found_users.add(username)
                    log.warning(f"{YELLOW}[Users]{RESET} Found user via author ID: {GREEN}{username}{RESET}")
    else:
        for i in range(1, max_users + 1):
            username = check_author(i)
            if username and username not in found_users:
                found_users.add(username)
                log.warning(f"{YELLOW}[Users]{RESET} Found user via author ID: {GREEN}{username}{RESET}")

    # --- Method 3: Parse HTML ---
    try:
        res = session.get(base_url, timeout=5)
        matches = re.findall(r'/author/([^/]+)/', res.text, re.IGNORECASE)
        for username in matches:
            if username not in found_users:
                found_users.add(username)
                log.warning(f"{YELLOW}[Users]{RESET} Found user via HTML metadata: {GREEN}{username}{RESET}")
    except Exception as e:
        log.warning(f"{RED}[Users]{RESET} HTML parsing failed: {e}")

    if not found_users:
        log.info(f"{CYAN}[Users]{RESET} No usernames found.")