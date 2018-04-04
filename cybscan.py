import json, re, os, time, random, socket
import sys
from sys import*

print('First of all you need to install all module from requirements.txt...')
print('Open requirements file and come back after installing all module...')
print('---------------------------------------------------')
print('If you have installed all module then press y')
choice = input()
if choice=='y' or choice=='Y':
    pass
else:
    sys.exit()

__author__ = 'Cyb3r3x3r'
Version = '0.1.0'

# Cybscan - Scanner of Wordpress Websites
# Copyright Cyb3r3x3r -- Indian Cyber Ghosts
# http://www.sniperhacks.wordpress.com
# Copyright editing will not make you programmer xD ;)
try:
    from bs4 import BeautifulSoup
except ImportError:
    print('[-] bs4 module not found')
    print('[!] install it by pip install bs4')
try:
    import requests
except :
    print('---------------------------------------------------')
    print('[+]requests Module not found')
    print('[-]install by pip install requests')
    sys.exit()
e = '\033[1;m'
try:
    from colorama import Fore, Back, Style

    g = Fore.GREEN
    y = Fore.YELLOW
    w = Fore.WHITE
    m = Fore.MAGENTA
    r = Fore.RED
    res = Style.RESET_ALL
except:
    print('---------------------------------------------------')
    print('[+]colorama Module not found')
    print('[-]install by pip install colorama')
    sys.exit()
    
class cybscan():
    def __init__(self):
        try:
            self.url = sys.argv[1]
        except IndexError:
            self.clscr()
            self.logo()
            self.direction()
            sys.exit()
        if self.url.startswith('http://'):
            self.url = self.url.replace('http://','')
        elif self.url.startswith('https://'):
            self.url = self.url.replace('https://','')
        else:
            pass
        url_cont = self.url
        try:
            ip = socket.gethostbyname(url_cont)
            self.CheckWordpress = requests.get('http://' + self.url, timeout=5)
            if '/wp-content/' in self.CheckWordpress.text:
                self.clscr()
                self.logo()
                print(y + '---------------------------------------' + res)
                print(g + '   [' + w + '+' + g + ']' + w + 'URL       : ' + m + self.url + e)
                print(g + '   [' + w + '+' + g + ']' + w + 'IP Server : ' + m + ip + e)
                print(g + '   [' + w + '+' + g + ']' + w + 'Server    : ' + m + self.CheckWordpress.headers[
                    'server'] + e)
                print(y + '---------------------------------------' + res)
               #self.version_grab()
                self.grab_theme()
                print(y + '---------------------------------------' + res)
                print(m + ' [~] Checking HoneyPot Probability............' + e)
                self.honeypot(ip)
                print(y + '---------------------------------------' + res)
                self.grab_plugin()
                if self.grab_plugin() == None:
                    print('{} [-]Unable to find plugins{}'.format(r,e))
                print(y + '---------------------------------------' + res)
                usr_choice = input(y + '    [!]' + w + 'Do you want to enumerate all usernames :' + y + '[Y/n]' + e)
                if usr_choice == 'n' or usr_choice == 'N':
                    print('{} [!]Username Enumeration Canceled{}'.format(y,e))
                    pass
                else:
                    self.Username_enum()
                print(y + '---------------------------------------' + res)
                print('{} [!]Retrieving Links from url{}'.format(y,e))
                self.links()
                print('{} [!] Quitting Now.............{}'.format(y,res))
                quit()
            else:
                self.clscr()
                self.logo()
                self._wrong()
                sys.exit()
        except socket.gaierror:
            self.clscr()
            self.logo()
            print(m + '------------------------------------------' + e)
            print(m +'    [' + r + '+' + r + ']' + w + 'Error Detected!: ' + m + '   [ ' \
                  + m + 'May be target url without / ....try again ' + w + '   ]  ' + e )
            sys.exit()
        except requests.exceptions.ReadTimeout:
                self.clscr()
                self.logo()
                print(y + '---------------------------------------------------')
                print(r + '    [' + y + '+' + r + ']' + m + ' TimedOut: ' + y + '    [ ' + w + \
                      ' ConnectionError! Maybe server is down , Or your ip s blocked ' + y + ']' + e)

    def direction(self):
        try:
            print(g + '------------------------------------------' + e)
            print(g +'    [' + y + '+' + y + ']' + w + 'usage: ' + m + '   [ ' \
                  + g + ' python cybscan.py domain.com ' + w + '   ]  ' + e)
        except:
            pass
    def wrong(self):
        try:
            print(g + '------------------------------------------')
            print(m +'    [' + r + '+' + r + ']' + w + 'Error Detected!: ' + m + '   [ ' \
                  + m + 'Not a valid domain ' + w + '   ]  ')
        except:
            pass
    def _wrong(self):
        try:
            print(g + '------------------------------------------')
            print(r +'    [' + r + '+' + r + ']' + w + 'Wordpress Error: ' + m + '   [ ' \
                  + r + ' Not a wordpress site ' + w + '   ]  ')
        except:
            pass

    def logo(self):

        print("""
         ##################################################
         #    ______   ______ ____   ____    _    _   _   #
         #   / ___\ \ / / __ ) ___| / ___|  / \  | \ | |  #
         #  | |    \ V /|  _ \___ \| |     / _ \ |  \| |  #
         #  | |___  | | | |_) |__) | |___ / ___ \| |\  |  #
         #   \____| |_| |____/____/ \____/_/   \_\_| \_|  #
         #   Developed By Cyb3r3x3r ----- ICG             #
         #        Sniperhacks.wordpress.com               #
         ##################################################

""")
    def clscr(self):
        linux = 'clear'
        windows = 'cls'
        os.system([linux,windows][os.name == 'nt'])

    def Username_enum(self):
        print(m +'[~] Scanning Useraname ....')
        usernamez = []
        try:
            for n in range(0,500):
                usn = requests.get('https://' + self.url + '/?cyb=x&author=' + str(n)).text
                response = re.search('/author/[^<]*/', usn)
                if response:
                    username = response.group().split('/author/')[1][:-4]
                    print(g + '     [+]' + w + 'Username:           ' + g + username.replace('/feed/','') + res)
                    usernamez.append(username)
                else:
                    if n - len(usernamez) > 10: 
                        print(r + '    [-]' + w + 'No username found ....may be all usernames are enumerated')
                        print(y + '    [!]Continuing...' + res)
                        break
        except Exception:
            print('{} [-] Looks like no username can be found....{}'.format(r,res))
    def plugin_vuln_test(self, plugin_name,flag):
        c = 0
        if flag == 0:
            name = "theme"
        else:
            name = "plugin"
        test_url = 'https://wpvulndb.com/search?utf8=✓&text=' + plugin_name
        test1 = requests.get(test_url, timeout=10)
        if 'No results found.' in test1.text:
            print(y + ' [!]' + name + ' don\'t seeem to be vulnerable' + res)
        else:
            test2 = re.findall('<td><a href="/vulnerabilities/(.*)">', test1.text)
            ab = (len(test2) /2)
            for x in range(int(ab)):
                cb = 'www.wpvulndb.com/vulnerabilities/' + str(test2[c])
                grab_title = requests.get('http://' + cb, timeout=5)
                title = re.findall('<title>(.*)</title>', grab_title.text)
                print(r + '   [' + w + '!' + w + ']' + r + cb + ' may be Vulnerable' + m + \
                        title[0].split('-')[0])
                c = c + 2
            c = 0

    def grab_plugin(self):
        try:
            plugin_nm = {}
            rm_plug = 'sniperhacks.wordpress.com'
            ac = re.findall('/wp-content/plugins/(.*)',self.CheckWordpress.text)
            s = 0
            test2 = len(ac)
            for x in range(int(test2)):
                names = ac[s].split('/')[0]
                if '?ver=' in ac[s]:
                    verzion = ac[s].split('?ver=')[1]
                    vers = re.findall('([0-9].[0-9].[0-9])',verzion)
                    if len(vers) == 0:
                        if '-' in str(names):
                            g1 = names.replace('-', ' ')
                            plugin_nm[g1] = s
                        elif '_' in str(names):
                            h1 = names.replace('_', ' ')
                            plugin_nm[h1] = s

                        else:
                            plugin_nm[names] = s
                    else:
                        ok_ver = names + ' ' + vers[0]
                        rm_plug = names
                        if '-' in ok_ver:
                            ff = ok_ver.replace('-', ' ')
                            plugin_nm[ff] = s
                        elif '_' in ok_ver:
                            fs = ok_ver.replace('_', ' ')
                            plugin_nm[fs] = s
                        else:
                            plugin_nm[ok_ver] = s
                else:
                    if rm_plug in names:
                        pass
                    else:
                        if '-' in str(names):
                            g1 = names.replace('-', ' ')
                            plugin_nm[g1] = s
                        elif '_' in str(names):
                            h1 = names.replace('_', ' ')
                            plugin_nm[h1] = s
                        else:
                            plugin_nm[names] = s
                s = s + 1
            for names_plug in plugin_nm:
                print(g + '  [ ' + w + '+' + g + ']' + m + 'Plugin Name : ' + g + names_plug)
                self.plugin_vuln_test(names_plug,1)
        except:
            print('{} [-]Unable to find plugins{}'.format(r,e))
        
    def grab_theme(self):
        ac = re.findall('/wp-content/themes/(.*)', self.CheckWordpress.text)
        theme_nm = ac[0].split('/')[0]
        ok_ver = theme_nm
        if '-' in ok_ver:
            x2 = ok_ver.replace('-', ' ')
            print(r + '    [' + w + '+' + g + ']' + w + ' Themes Name: ' + m + x2)
            self.plugin_vuln_test(x2,0)
        elif '_' in ok_ver:
            x3 = ok_ver.replace('_', ' ')
            print(r + '    [' + y + '+' + r + ']' + w + ' Themes Name: ' + m + x3)
            self.plugin_vuln_test(x3,0)
        else:
            print(r + '    [' + y + '+' + r + ']' + w + ' Themes Name: ' + m + ok_ver)
            self.plugin_vuln_test(ok_ver,0)
        
        if '-' in theme_nm:
            x2 = theme_nm.replace('-', ' ')
            print(r + '    [' + y + '+' + r + ']' + w + ' Themes Name: ' + m + x2)
            self.plugin_vuln_test(x2,0)
        elif '_' in theme_nm:
            x3 = theme_nm.replace('_', ' ')
            print(r + '    [' + y + '+' + r + ']' + w + ' Themes Name: ' + m + x3)
            self.plugin_vuln_test(x3,0)
        else:
            print(r + '    [' + y + '+' + r + ']' + w + ' Themes Name: ' + m + theme_nm)
            self.plugin_vuln_test(ok_ver,0)

    def honeypot(self,ip):
        match = {"0.0": 0, "0.1": 10, "0.2": 20, "0.3": 30, "0.4": 40, "0.5": 50, "0.6": 60, "0.7": 70, "0.8": 80, "0.9": 90, "1.0": 10}
        try:
            gethoney = requests.get('https://api.shodan.io/labs/honeyscore/' + str(ip) + '?key=C23OXE0bVMrul2YeqcL7zxb6jZ4pj2by').text
            print('{} [+] HoneyPot Check Result = {}{}'.format(g,gethoney,e))
            print('{} [+] HoneyPot Probability Result = {}{}'.format(g,match[gethoney],e))
            check = float(gethoney)
            if check >= 0.0 and check <= 0.4:
                print('{}  [+] Looks like it is a REAL SYSTEM {}'.format(g,e))
            else:
                print('{}  [-] Oh! It is a HONEYPOT SYSTEM {}'.format(r,e))
        except:
            print('{}[-] It looks like HoneyPot Check can not be completed.{}'.format(r,e))

    def links(self):
        tar = 'http://' + self.url
        page = requests.get(tar)
        data = page.text
        soup = BeautifulSoup(data,"lxml")
        choice = input('{} [?]Do you want to save the retrieved links[Y/n]{}'.format(y,e))
        if choice == 'n' or choice == 'N':
            for link in soup.find_all('a'):
                if 'javascript:void' in link.get('href'):
                    pass
                else:
                    print(link.get('href'))
            print('{} [+] Looks like all the links are retrieved{}'.format(g,e))
        else:
            print('{} [!] Enter the name of the file where u want to save the links{}'.format(y,e))
            file = str(input('> '))
            file = file + '.txt'
            print('{} [+]All the links will be saved to {}{}'.format(g,file,e))
            f = open(file,"w+")
            for link in soup.find_all('a'):
                if 'javascript:void' in link.get('href'):
                    pass
                else:
                    print(link.get('href'))
                    f.write(str(link.get('href')))
                    f.write('\n')
            print('{} [+]All the links are saved to {}{}'.format(g,file,e))
            print('{} [+] Looks like all the links are retrieved{}'.format(g,e))
    
cyb = cybscan()
cyb
