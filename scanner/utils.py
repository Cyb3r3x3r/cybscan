# scanner/utils.py
import re

def strip_scheme(url):
    return re.sub(r"^https?://", "", url)

def is_wordpress(html):
    return "/wp-content/" in html

def print_logo():
    from scanner.colors import CYAN, MAGENTA, BOLD, RESET

    print(f"""{BOLD}{CYAN}
     ##################################################
     #    ______   ______ ____   ____    _    _   _   #
     #   / ___\\ \\ / / __ ) ___| / ___|  / \\  | \\ | |  #
     #  | |    \\ V /|  _ \\___ \\| |     / _ \\ |  \\| |  #
     #  | |___  | | | |_) |__) | |___ / ___ \\| |\\  |  #
     #   \\____| |_| |____/____/ \\____/_/   \\_\\_| \\_|  #
     #                                                #
     #         {MAGENTA}Developed By Cyb3r3x3r{CYAN}               #
     ##################################################{RESET}
""")