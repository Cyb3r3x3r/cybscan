# Cybscan - Scanner of Wordpress Websites By CYB3R3X3R
# https://github.com/cyb3r3x3r
__author__ = 'Cyb3r3x3r'
Version = '1.1.6'

# main.py
import argparse
import logging
from scanner.core import Scanner
from scanner.utils import print_logo
from scanner.security import load_wordlist_from_file
import urllib3


def setup_logger():
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)  # Remove all previous handlers

    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",  # Show only the message
        handlers=[logging.StreamHandler()]
    )

def parse_args():
    parser = argparse.ArgumentParser(description="CybScan - WordPress Vulnerability Scanner")
    parser.add_argument("url", help="Target website URL (e.g., example.com)")
    parser.add_argument("--save-links", action="store_true", help="Save crawled links to file")
    parser.add_argument("--enumerate-users", action="store_true", help="Attempt to enumerate usernames")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL certificate verification (insecure)")
    parser.add_argument("--include-mu", action="store_true", help="Include detection of mu-plugins like Jetpack")
    parser.add_argument('--thread', type=int, default=1, help="Enable multithreaded mode with specified number of threads")
    parser.add_argument(
    "--admin-wordlist",
    help="Path to a custom wordlist for admin/login panels",
    type=str,
    default=None
)
    return parser.parse_args()

def main():
    setup_logger()
    print_logo()
    args = parse_args()

    if args.no_verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        verify_ssl = False
    else:
        verify_ssl = True

    if args.admin_wordlist:
        wordlist = load_wordlist_from_file(args.admin_wordlist)
    else:
        wordlist = None

    scanner = Scanner(args.url, verify=verify_ssl, include_mu=args.include_mu,thread_count=args.thread)
    scanner.run(save_links=args.save_links, enumerate_users=args.enumerate_users,wordlist=wordlist)

if __name__ == "__main__":
    main()
