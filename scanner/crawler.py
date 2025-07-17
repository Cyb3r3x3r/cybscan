from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from scanner.colors import GREEN, RED, YELLOW, RESET,CYAN
import time
import logging
import socket
import whois
import threading
import random

log = logging.getLogger("CybScan")
def crawl_site(base_url, session, save_links=False, output_file="links.txt", max_depth=2, thread_count=5):
    """
    Crawl internal links on a website up to a specified depth using multithreading.
    """
    log.info(f"{YELLOW}[Crawler]{RESET} Starting link crawl...")

    visited = set()
    to_visit = [(base_url, 0)]
    collected_links = set()
    domain = urlparse(base_url).netloc
    lock = threading.Lock()

    def fetch_links(current_url, depth):
        local_links = []
        try:
            res = session.get(current_url, timeout=5)
            soup = BeautifulSoup(res.text, "lxml")
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"]
                joined_url = urljoin(current_url, href)
                parsed = urlparse(joined_url)

                if parsed.netloc != domain:
                    continue  # Skip external links

                final_url = parsed.scheme + "://" + parsed.netloc + parsed.path

                with lock:
                    if final_url not in visited:
                        visited.add(final_url)
                        collected_links.add(final_url)
                        local_links.append((final_url, depth + 1))
                        log.info(f"{GREEN}[Crawler]{RESET} Found: {final_url}")
        except Exception as e:
            log.warning(f"{RED}[Crawler]{RESET} Failed to fetch {current_url}: {e}")
        return local_links

    while to_visit:
        current_batch = to_visit
        to_visit = []

        with ThreadPoolExecutor(max_workers=thread_count) as executor:
            futures = [executor.submit(fetch_links, url, depth) for url, depth in current_batch]
            for future in as_completed(futures):
                new_links = future.result()
                to_visit.extend([link for link in new_links if link[1] <= max_depth])

    if save_links and collected_links:
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                for link in sorted(collected_links):
                    f.write(link + "\n")
            log.info(f"{GREEN}[Crawler]{RESET} ✅ Saved {len(collected_links)} links to {output_file}")
        except Exception as e:
            log.warning(f"{RED}[Crawler]{RESET} Failed to save links: {e}")


def detect_honeypot(base_url, session):
    log.info(f"{CYAN}[Honeypot]{RESET} Checking for honeypot indicators...")
    parsed = urlparse(base_url)
    hostname = parsed.netloc

    try:
        # 1. Reverse DNS lookup
        ip = socket.gethostbyname(hostname)
        rdns = socket.gethostbyaddr(ip)[0]
        if "honeypot" in rdns or "secureserver" in rdns:
            log.warning(f"{RED}[Honeypot]{RESET} ⚠ Possible honeypot via reverse DNS: {YELLOW}{rdns}{RESET}")
        else:
            log.debug(f"{CYAN}[Honeypot]{RESET} Reverse DNS lookup: {rdns}")
    except Exception as e:
        log.debug(f"{CYAN}[Honeypot]{RESET} Reverse DNS failed: {e}")

    try:
        # 2. WHOIS check
        domain_info = whois.whois(hostname)
        if domain_info and any("spam" in str(v).lower() or "abuse" in str(v).lower() for v in domain_info.values()):
            log.warning(f"{RED}[Honeypot]{RESET} ⚠ Suspicious WHOIS data (spam/abuse flags)")
        else:
            log.debug(f"{CYAN}[Honeypot]{RESET} WHOIS lookup complete")
    except Exception as e:
        log.debug(f"{CYAN}[Honeypot]{RESET} WHOIS check failed: {e}")

    try:
        # 3. Fake path probe
        random_path = "/cybscan-probe-" + str(random.randint(1000, 9999))
        test_url = base_url.rstrip("/") + random_path
        res = session.get(test_url, timeout=5)
        if res.status_code in (200, 403) and len(res.text.strip()) < 300:
            log.warning(f"{RED}[Honeypot]{RESET} ⚠ Uniform response to fake path: {YELLOW}{test_url} → {res.status_code}{RESET}")
        else:
            log.debug(f"{CYAN}[Honeypot]{RESET} Probe {test_url} returned status {res.status_code}")
    except Exception as e:
        log.debug(f"{CYAN}[Honeypot]{RESET} Fake probe test failed: {e}")

    log.info(f"{CYAN}[Honeypot]{RESET} Honeypot detection complete.")