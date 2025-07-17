# scanner/core.py
import logging
import socket
import requests
from scanner.utils import strip_scheme, is_wordpress
from scanner.security import is_self_hosted_wordpress,check_brute_force_protection,check_admin_panel_exposure,detect_admin_endpoints
from scanner.version import detect_wp_version
from scanner.colors import RED, GREEN, CYAN, YELLOW, RESET
from scanner.headers import (
    check_http_headers,
    check_rss_feeds,
    check_directory_indexing,
    check_xmlrpc
)
from scanner.assets import detect_theme, detect_plugins,enumerate_wp_users
from scanner.crawler import crawl_site,detect_honeypot

log = logging.getLogger("CybScan")

class Scanner:
    def __init__(self, target_url, thread_count,verify=True, include_mu=False):
        self.url = strip_scheme(target_url)
        self.session = requests.Session()
        self.session.verify = verify
        self.base_url = f"http://{self.url}"
        self.include_mu = include_mu
        self.thread_count = thread_count

    def run(self, wordlist,save_links=False, enumerate_users=False):
        try:
            ip = socket.gethostbyname(self.url)
            log.info(f"{CYAN}Target IP: {ip}{RESET}")
        except Exception as e:
            log.error(f"{RED}Could not resolve domain: {e}{RESET}")
            return

        try:
            resp = self.session.get(self.base_url, timeout=5)
        except requests.RequestException as e:
            log.error(f"{RED}Failed to connect: {e}{RESET}")
            return

        if not is_wordpress(resp.text):
            log.warning(f"{RED}Target is not a WordPress site.{RESET}")
            return

        log.info(f"{GREEN}[+]Target is a WordPress site.{RESET}")
        log.info(f"{GREEN}[+]WordPress site detected.{RESET}")
        detect_wp_version(self.base_url, self.session)
        check_http_headers(self.url)
        if enumerate_users:
            enumerate_wp_users(self.base_url, self.session, thread_count=self.thread_count)
        check_rss_feeds(self.base_url, self.session)
        check_directory_indexing(self.base_url, self.session)
        check_xmlrpc(self.base_url, self.session)
        detect_theme(self.base_url, self.session,thread_count=self.thread_count)
        detect_plugins(self.base_url,self.session,thread_count=self.thread_count,include_mu=self.include_mu)
        #crawl_site(self.base_url,self.session,save_links=save_links,thread_count=self.thread_count)
        detect_honeypot(self.base_url, self.session)
        if is_self_hosted_wordpress(self.base_url, self.session):
            check_brute_force_protection(self.base_url, self.session)
        check_admin_panel_exposure(self.base_url, self.session)
        detect_admin_endpoints(self.base_url, self.session, wordlist=wordlist, thread_count=self.thread_count)