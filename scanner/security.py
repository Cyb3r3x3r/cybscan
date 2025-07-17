import time
from urllib.parse import urljoin
from scanner.colors import GREEN, YELLOW, RED, CYAN, RESET
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
log = logging.getLogger("CybScan")


DEFAULT_ADMIN_PATHS = [
    "/admin/",
    "/admin/login/",
    "/administrator/",
    "/login/",
    "/user/login/",
    "/wp-login.php",
    "/wp-admin/",
    "/wp-admin/admin.php",
    "/wp-admin/install.php",
    "/dashboard/",
    "/cms/",
    "/panel/",
    "/backend/",
    "/controlpanel/",
    "/adminpanel/",
    "/wp-content/plugins/adminer/adminer.php"
]


def load_wordlist_from_file(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            return lines
    except Exception as e:
        log.warning(f"[Discover] Failed to read custom wordlist: {e}")
        return []
    
def detect_admin_endpoints(base_url, session, wordlist=None, thread_count=5):
    """
    Attempts to discover exposed admin/login endpoints using wordlist.
    Uses multithreading.
    """
    log.info(f"{CYAN}[Discover]{RESET} Scanning for admin/login paths...")

    if not wordlist:
        wordlist = DEFAULT_ADMIN_PATHS

    def check_path(path):
        full_url = urljoin(base_url, path)
        try:
            res = session.get(full_url, timeout=5, allow_redirects=True)
            code = res.status_code

            if code == 200:
                log.warning(f"{YELLOW}[Discover]{RESET} Found: {path} [Status: {code}]")
            elif code in (401, 403):
                log.info(f"{CYAN}[Discover]{RESET} Restricted: {path} [Status: {code}]")
            elif code in (301, 302):
                log.info(f"{CYAN}[Discover]{RESET} Redirected: {path} [Status: {code}]")
            elif code == 404:
                pass  # Silent on 404
            else:
                log.info(f"{CYAN}[Discover]{RESET} {path} [Status: {code}]")
        except Exception as e:
            log.warning(f"{RED}[Discover]{RESET} Error on {path}: {e}")

    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = [executor.submit(check_path, path) for path in wordlist]
        for _ in as_completed(futures):
            pass

    log.info(f"{CYAN}[Discover]{RESET} Admin path scan complete.")


def is_self_hosted_wordpress(base_url, session):
    """
    Checks if /wp-login.php is self-hosted or redirects to wordpress.com
    """
    login_url = urljoin(base_url, "/wp-login.php")
    try:
        res = session.get(login_url, timeout=5, allow_redirects=True)
        if "wordpress.com/log-in" in res.url:
            log.info(f"{CYAN}[BruteForce]{RESET} Login redirects to WordPress.com — skipping brute-force protection check.")
            return False
        return True
    except Exception as e:
        log.warning(f"{YELLOW}[BruteForce] Failed to resolve wp-login.php: {e}{RESET}")
        return False


def check_brute_force_protection(base_url, session):
    """
    Tries a few failed POST attempts to /wp-login.php and checks if behavior changes (rate-limiting, CAPTCHA, etc.)
    """
    login_url = urljoin(base_url, "/wp-login.php")

    fake_user = "cybscan"
    fake_pass = "wrongpass123!"
    headers = {
        "User-Agent": "CybScan-BruteForce-Test"
    }
    data = {
        "log": fake_user,
        "pwd": fake_pass,
        "wp-submit": "Log In",
        "redirect_to": base_url,
        "testcookie": "1"
    }

    try:
        log.info(f"{CYAN}[BruteForce]{RESET} Sending repeated failed login attempts...")

        responses = []
        for i in range(3):
            res = session.post(login_url, data=data, headers=headers, timeout=5)
            responses.append(res.text)
            time.sleep(1)

        # Analyze differences in responses
        unique_responses = len(set(responses))
        if unique_responses > 1:
            log.info(f"{YELLOW}[BruteForce]{RESET} Login responses changed after multiple attempts — protection may be in place.")
        else:
            log.warning(f"{RED}[BruteForce]{RESET} No noticeable protection or rate-limiting detected.")
    except Exception as e:
        log.warning(f"{YELLOW}[BruteForce] Failed during login attempts: {e}{RESET}")


def check_admin_panel_exposure(base_url, session):
    """
    Checks for exposure of key WordPress admin interfaces:
    - /wp-admin/
    - /wp-login.php
    - /wp-admin/install.php
    """
    log.info(f"{CYAN}[Admin]{RESET} Checking for exposed admin panels...")

    targets = {
        "/wp-admin/": "Admin Dashboard",
        "/wp-login.php": "Login Page",
        "/wp-admin/install.php": "Installer"
    }

    for path, name in targets.items():
        url = urljoin(base_url, path)
        try:
            res = session.get(url, timeout=5, allow_redirects=True)
            status = res.status_code

            if status == 200:
                log.warning(f"{YELLOW}[Admin]{RESET} {name} exposed at {url} [Status: {status}]")
            elif status == 403:
                log.info(f"{CYAN}[Admin]{RESET} {name} is restricted [Status: {status}]")
            elif status == 302:
                log.info(f"{CYAN}[Admin]{RESET} {name} redirected (Login protected) [Status: {status}]")
            elif status == 404:
                log.info(f"{GREEN}[Admin]{RESET} {name} not found [Status: {status}]")
            else:
                log.info(f"{CYAN}[Admin]{RESET} {name} returned status {status}")
        except Exception as e:
            log.warning(f"{RED}[Admin]{RESET} Failed to check {name}: {e}")
