# Cybscan - Scanner of Wordpress Websites By CYB3R3X3R
# https://github.com/cyb3r3x3r
# Copying will not make you programmer xD ;)
__author__ = 'Cyb3r3x3r'
Version = '0.1.6'

import json, re, os, time, random, socket, sys
from sys import*
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
    print('[+]Please install all modules fron requirements.txt file')
if sys.version[0] > '2':
    pass
else:
    print("[{}WARNING{}] You are using Python 2...Install Python 3 to use CybScan".format(r,r))
    print("[{}INFO{}] A version for Python 2 may be avaiable in future".format(g,g))
    sys.exit()
try:
    from bs4 import BeautifulSoup
except ImportError:
    print('[-] bs4 module not found')
    print('[+]Please install all modules fron requirements.txt file')
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
except :
    print('---------------------------------------------------')
    print('[+]Please install all modules fron requirements.txt file')
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
e = '\033[1;m'

    
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
            self.CheckWordpress = requests.get('http://' + self.url, timeout=5, verify=False)
            if '/wp-content/' in self.CheckWordpress.text:
                self.clscr()
                self.logo()
                print(y + '---------------------------------------' + res)
                print(g + '   [' + w + '+' + g + ']' + w + 'URL       : ' + m + self.url + e)
                print(g + '   [' + w + '+' + g + ']' + w + 'IP Server : ' + m + ip + e)
                try:
                    print(g + '   [' + w + '+' + g + ']' + w + 'Server    : ' + m + self.CheckWordpress.headers[
                    'server'] + e)
                except Exception:
                    print(' {}[-] Some problem occured getting server....{}'.format(r,e))
                print(y + '---------------------------------------' + res)
                self.wp_version()
                print(y + '---------------------------------------' + res)
                self.grab_http()
                print(y + '---------------------------------------' + res)
                self.check_rss()
                print(y + '---------------------------------------' + res)
                print(m + ' [~] Checking if Directory Indexing is enabled............' + e)
                time.sleep(2)
                self.dir_index()
                print(y + '---------------------------------------' + res)
                self.xmlrpc()
                print(y + '---------------------------------------' + res)
                self.grab_theme()
                print(y + '---------------------------------------' + res)
                print(m + ' [~] Checking HoneyPot Probability............' + e)
                self.honeypot(ip)
                print(y + '---------------------------------------' + res)
                self.grab_plugin()
                if self.grab_plugin() == None:
                    print('{} [-]Unable to find more plugins{}'.format(r,e))
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
                print(Style.RESET_ALL)
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
         #          Developed By Cyb3r3x3r                #
         #                                                #
         ##################################################

""")
    def clscr(self):
        linux = 'clear'
        windows = 'cls'
        os.system([linux,windows][os.name == 'nt'])

    def Username_enum(self):
        print(m +'[~] Scanning Useraname ....')
        usernamez = []
        usrn = '0'
        usr_flag = 0
        try:
            for n in range(0,500):
                if usr_flag == 6:
                    print(y + '   [!]Looks like all usernames are enumerated...' + res)
                    break;
                usn = requests.get('https://' + self.url + '/?cyb=x&author=' + str(n), verify=False).text
                response = re.search('/author/[^<]*/', usn)
                if response:
                    username = response.group().split('/author/')[1][:-4]
                    username = username.replace('/feed/','')
                    if username == usrn:
                        usr_flag += 1
                        continue
                    print(g + '     [+]' + w + 'Username:           ' + g + username + res)
                    usrn = username
                    usernamez.append(username)
                else:
                    if n - len(usernamez) > 10: 
                        print(r + '    [-]' + w + 'No username found ....may be nothing is available now')
                        print(y + '    [!]Continuing...' + res)
                        break
        except Exception:
            print('{} [-] Looks like no username can be found....{}'.format(r,res))
    def plugin_vuln_test(self, plugin_name,flag):
        c = 0
        if flag == 0:
            name = "theme"
        elif flag == 2:
            name = "version"
        else:
            name = "plugin"
        test_url = 'https://wpvulndb.com/search?utf8=✓&text=' + plugin_name
        test1 = requests.get(test_url, timeout=10, verify=False)
        if 'No results found.' in test1.text:
            print(y + ' [!]' + name + ' don\'t seeem to be vulnerable' + res)
        else:
            test2 = re.findall('<td><a href="/vulnerabilities/(.*)">', test1.text)
            ab = (len(test2) /2)
            for x in range(int(ab)):
                cb = 'www.wpvulndb.com/vulnerabilities/' + str(test2[c])
                grab_title = requests.get('http://' + cb, timeout=5, verify=False)
                title = re.findall('<title>(.*)</title>', grab_title.text)
                print(r + '   [' + w + '!' + w + ']' + r + cb + ' may be Vulnerable' + m + \
                        title[0].split('-')[0])
                c = c + 2
            c = 0

    def grab_plugin(self):
        plugin_list = []
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
                if names_plug in plugin_list:
                    pass
                else:
                    print(g + '  [ ' + w + '+' + g + ']' + m + 'Plugin Name : ' + g + names_plug)
                    self.plugin_vuln_test(names_plug,1)
                    plugin_list.append(names_plug)
        except:
            print('{} [-]Unable to find plugins{}'.format(r,e))
        
    def grab_theme(self):
        theme_list = []
        ac = re.findall('/wp-content/themes/(.*)', self.CheckWordpress.text)
        theme_nm = ac[0].split('/')[0]
        ok_ver = str(theme_nm)
        if '-' in ok_ver:
            x2 = ok_ver.replace('-', ' ')
            if x2 in theme_list:
                pass
            else:
                print(m + '    [' + w + '+' + g + ']' + w + ' Themes Name: ' + g + x2)
                self.plugin_vuln_test(x2,0)
                theme_list.append(x2)
        elif '_' in ok_ver:
            x3 = ok_ver.replace('_', ' ')
            if x3 in theme_list:
                pass
            else:
                print(m + '    [' + w + '+' + g + ']' + w + ' Themes Name: ' + g + x3)
                self.plugin_vuln_test(x3,0)
                theme_list.append(x3)
        else:
            if ok_ver in theme_list:
                pass
            else:
                print(m + '    [' + w + '+' + g + ']' + w + ' Themes Name: ' + g + ok_ver)
                self.plugin_vuln_test(ok_ver,0)
                theme_list.append(ok_ver)
        
        if '-' in theme_nm:
            x2 = theme_nm.replace('-', ' ')
            if x2 in theme_list:
                pass
            else:
                print(m + '    [' + w + '+' + g + ']' + w + ' Themes Name: ' + g + x2)
                self.plugin_vuln_test(x2,0)
                theme_list.append(x2)
        elif '_' in theme_nm:
            x3 = theme_nm.replace('_', ' ')
            if x3 in theme_list:
                pass
            else:
                print(m + '    [' + w + '+' + g + ']' + w + ' Themes Name: ' + g + x3)
                self.plugin_vuln_test(x3,0)
                theme_list.append(x3)
        else:
            if ok_ver in theme_list:
                pass
            else:
                print(m + '    [' + w + '+' + g + ']' + w + ' Themes Name: ' + g + ok_ver)
                self.plugin_vuln_test(ok_ver,0)
                theme_list.append(ok_ver)
    def honeypot(self,ip):
        match = {"0.0": 0, "0.1": 10, "0.2": 20, "0.3": 30, "0.4": 40, "0.5": 50, "0.6": 60, "0.7": 70, "0.8": 80, "0.9": 90, "1.0": 10}
        try:
            gethoney = requests.get('https://api.shodan.io/labs/honeyscore/' + str(ip) + '?key=C23OXE0bVMrul2YeqcL7zxb6jZ4pj2by', verify=False).text
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
        page = requests.get(tar, verify=False)
        data = page.text
        try:
            soup = BeautifulSoup(data,"lxml")
            choice = input('{} [?]Do you want to save the retrieved links[Y/n]{}'.format(y,e))
            if choice == 'n' or choice == 'N':
                for link in soup.find_all('a'):
                    if 'javascript:void' in str(link.get('href')):
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
                    if 'javascript:void' in str(link.get('href')):
                        pass
                    else:
                        f.write(str(link.get('href')))
                        f.write('\n')

                time.sleep(2)
                print('{} [+]All the links are saved to {}{}'.format(g,file,e))
                print('{} [+] Looks like all the links are retrieved{}'.format(g,e))
        except Exception:
            print('[-] Looks like lxml is not working or nor installed correctly...try reinstalling{}'.format(r,e))
    def grab_http(self):
        checker = 'http://api.hackertarget.com/httpheaders/?q='
        check_headers = requests.get(checker + self.url,verify=False)
        print('{}[+] HTTP Headers Information Retrieved - {}'.format(g,e))
        print('{}[*]{}{}'.format(m,check_headers.text,e))

    def wp_version(self):
        tocheck = self.url
        version = []
        def current_ver():
            wpurl = 'http://wordpress.org/download/'
            data = requests.get(wpurl,verify=False).text
            regex = r"Download WordPress ([0-9.]+)"
            cur_ver = re.findall(regex,data)
            if len(cur_ver) == 0:
                pass
            else:
                wp_ver = y + ' [!] Current WordPress Version : - ' + cur_ver[0]
                return wp_ver
        def from_generator(url):
            regex = r"WordPress ([0-9.]+)"
            data = requests.get('http://' + url,verify=False).text
            version = re.findall(regex,data)
            if len(version) == 0:
                return False
            else:
                print('{} [+] Wordpress Version : -  {}{}'.format(g,version[0],e))
                print('{} [+] Version info found from meta generator tag {}'.format(g,e))
        def from_readme(url):
            checker = 'http://' + url + '/readme.html'
            data = requests.get(checker,verify=False).text
            regex = r"Version ([0-9.]+)"
            version = re.findall(regex,data)
            if len(version) == 0:
                return False
            else:
                print('{} [+] WordPress Version : - {}{}'.format(g,version[0],e))
                print('{} [+] Version info found from ReadMe page {}'.format(g,e))
        def from_html(url):
            checker = 'http://' + url
            data = requests.get(checker,verify=False).text
            regex = r"js\/wp(.*)'>"
            version1 = re.findall(regex,data)
            if len(version1) == 0:
                regex = r"js\\/wp(.*)\}\}"
                version1 = re.findall(regex,data)
                if len(version1) == 0:
                    return False
                else:
                    line = version1[0]
                    regex = r"ver=([0-9.]+)"
                    vers = re.findall(regex,line)
                    if len(vers) == 0:
                        return False
                    else:
                        print('{} [+] WordPress Version : - {}{}'.format(g,vers[0],e))
                        print('{} [+] Version info found from reading page source {}'.format(g,e))
            else:
                line = version1[0]
                regex = r"ver=([0-9.]+)"
                vers = re.findall(regex,line)
                if len(vers) == 0:
                    return False
                else:
                    print('{} [+] WordPress Version : - {}{}'.format(g,vers[0],e))
                    print('{} [+] Version info found from reading page source {}'.format(g,e))
        def from_rss(url):
            checker = 'http://' + url + '/feed/'
            data = requests.get(checker,verify=False).text
            regex = r"wordpress\.org\/\?v=([0-9.]+)"
            vers = re.findall(regex,data)
            if len(vers) == 0:
                return False
            else:
                print('{} [+] WordPress Version : - {}{}'.format(g,vers[0],e))
                print('{} [+] Version info found from reading RSS feed {}'.format(g,e))
        f = current_ver()
        a = from_readme(tocheck)
        if a is False:
            b = from_generator(tocheck)
            if b is False:
                c = from_html(tocheck)
                if c is False:
                    d = from_rss(tocheck)
                    if d is False:
                        print('{} [-] WordPress Version : not detected{}'.format(r,e))
                    else:
                        pass
                else:
                    pass
            else:
                pass
        else:
            pass
        print(f)
    def check_rss(self):
        target = 'http://' + self.url
        check1  = requests.get(target + '/feed/',verify=False)
        data = check1.text
        regex = r'\<atom:link href="(.+)" rel'
        link = re.findall(regex,data)
        stat = check1.status_code
        if stat == 200 and len(link) != 0:
            print(' {}[+] Interesting Page - RSS Feed {}'.format(g,e))
            print(' {}[+] Link : {}{}'.format(g,link[0],e))
        else:
            pass
        check1  = requests.get(target + '/comments/feed/',verify=False)
        data = check1.text
        regex = r'\<atom:link href="(.+)" rel'
        link = re.findall(regex,data)
        stat = check1.status_code
        if stat == 200 and len(link) != 0:
            print(' {}[+] Interesting Page - RSS Feed {}'.format(g,e))
            print(' {}[+] Link : {}{}'.format(g,link[0],e))
        else:
            pass
    def dir_index(self):
        checker = 'http://' + self.url + '/wp-content/uploads/'
        data = requests.get(checker,verify=False)
        stat = data.status_code
        if stat != 200:
            print('{} [+] Directory Indexing Checked{}'.format(g,e))
            print('{} [+] Directory Indexing is not enabled {}'.format(g,e))
        else:
            print('{} [-] Directory Indexing Checked{}'.format(r,e))
            print('{} [-] Directory Indexing is enabled {}'.format(r,e))
    def xmlrpc(self):
        checker = 'http://' + self.url + '/xmlrpc.php'
        res = requests.get(checker,verify=False)
        stat = res.status_code
        if stat == 405:
            print('{} [-] XML-RPC - Interface available at {}{}'.format(r,checker,e))
        else:
            print('{} [+] XML-RPC - Interfece not available {}'.format(g,e))

cyb = cybscan()
cyb
