import os
import re
import sys
import json
import requests
import random
import tldextract
import argparse
import time
from functools import partial
from multiprocessing.dummy import Pool
import subprocess
from threading import Thread
from queue import Queue
from time import sleep
from pathlib import Path
from getpass import getpass
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup

class Color:
    """Class to define terminal colors."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    PURPLE = "\033[35m"
    WHITE = "\033[97m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    ORANGE = "\033[38;5;208m"
    PINK = "\033[38;5;205m"

class OSINTToolkit:
    def __init__(self, domain, config, api_keys, output_dir, active=False, brute=False):
        """Initialize the OSINTToolkit."""
        if not self._is_valid_domain(domain):
            raise ValueError(f"Invalid domain: {domain}")
        self.domain = domain
        self.config = config
        self.api_keys = api_keys
        self.output_dir = Path(output_dir)
        self.active = active
        self.brute = brute
        self.resolvers = self._load_resolvers()
        self.wordlists = self._load_wordlists()
        self.unique_subdomains = set()
        self.unique_ips = set()
        self.t_history = []  
        self.t_history_urls = []  
        self._create_output_dir()
        self._check_required_tools()

    def _is_valid_domain(self, domain):
        """Validate domain name using regex."""
        pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(pattern, domain))

    def _load_resolvers(self):
        """Load DNS resolvers from file."""
        resolvers_file = self.config.get('wordlists', {}).get('resolvers', '')
        if resolvers_file and Path(resolvers_file).exists():
            with open(resolvers_file) as f:
                return [line.strip() for line in f if line.strip()]
        return ['1.1.1.1', '8.8.8.8', '9.9.9.9']

    def _load_wordlists(self):
        """Load DNS wordlist."""
        dns_wordlist = self.config.get('wordlists', {}).get('dns', '')
        if dns_wordlist and Path(dns_wordlist).exists():
            return Path(dns_wordlist)
        raise FileNotFoundError(f"DNS wordlist not found at {dns_wordlist}")

    def _create_output_dir(self):
        """Create output directory structure."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        subdirs = ['subdomains', 'ports', 'urls', 'emails', 'social_media', 'sensitive_files', 'js_files', 'cors', 'dir_brute', 'ips', 'shodan', 'github']
        for subdir in subdirs:
            (self.output_dir / subdir).mkdir(exist_ok=True)

    def _check_required_tools(self):
        """Check if required tools are installed."""
        tools = ['subfinder', 'httpx', 'katana', 'arjun', 'wpscan', 'ffuf', 'nuclei', 'subzy', 'curl', 'gau', 'dirsearch', 'naabu', 'nmap', 'masscan', 'jq']
        missing = [tool for tool in tools if subprocess.run(f"which {tool}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0]
        if missing:
            print(f"{Color.RED}[-] Missing tools: {', '.join(missing)}. Please install them.{Color.RESET}")

    def _run_command(self, command, task_name, output_file=None):
        """Execute shell command and handle output."""
        print(f"{Color.GREEN}[+] Running {task_name}...{Color.RESET}")
        try:
            result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
            if output_file:
                output_path = self.output_dir / output_file
                with open(output_path, 'w') as f:
                    f.write(result.stdout)
            print(f"{Color.GREEN}[+] {task_name} completed.{Color.RESET}")
            return result.stdout
        except subprocess.CalledProcessError as e:
            print(f"{Color.RED}[-] Error in {task_name}: {e}{Color.RESET}")
            return None

    # Subdomain Enumeration
    def _subfinder(self):
        """Find subdomains using subfinder."""
        self._run_command(
            f"subfinder -d {self.domain} -all -recursive > {self.output_dir}/subdomains/subdomain.txt",
            "Subfinder Enumeration",
            "subdomains/subdomain.txt"
        )

    def _filter_live_subdomains(self):
        """Filter out live subdomains using httpx."""
        self._run_command(
            f"cat {self.output_dir}/subdomains/subdomain.txt | httpx -ports 80,443,8080,8000,8888 -threads 200 > {self.output_dir}/subdomains/subdomains_alive.txt",
            "Live Subdomains Filtering",
            "subdomains/subdomains_alive.txt"
        )

    # VirusTotal API
    def _virustotal_report(self):
        """Get VirusTotal domain report including subdomains and IPs."""
        api_key = self.api_keys.get('virustotal', '')
        if not api_key:
            print(f"{Color.RED}[-] VirusTotal API key not provided{Color.RESET}")
            return
        # Full report
        self._run_command(
            f"curl -s 'https://www.virustotal.com/vtapi/v2/domain/report?apikey={api_key}&domain={self.domain}' > {self.output_dir}/subdomains/vt_report.json",
            "VirusTotal Report",
            "subdomains/vt_report.json"
        )
        # Extract IPs
        self._run_command(
            f"curl -s 'https://www.virustotal.com/vtapi/v2/domain/report?domain={self.domain}&apikey={api_key}' | jq -r '.. | .ip_address? // empty' | grep -Eo '([0-9]{{1,3}}\.){{3}}[0-9]{{1,3}}' > {self.output_dir}/ips/vt_ips.txt",
            "VirusTotal IP Extraction",
            "ips/vt_ips.txt"
        )
        # Extract subdomains
        self._run_command(
            f"curl -s 'https://www.virustotal.com/vtapi/v2/domain/report?apikey={api_key}&domain={self.domain}' | jq -r '.domain_siblings[]' > {self.output_dir}/subdomains/vt_subdomains.txt",
            "VirusTotal Subdomain Extraction",
            "subdomains/vt_subdomains.txt"
        )

    # AlienVault OTX
    def _alienvault_ip_extraction(self):
        """Extract IP addresses from AlienVault OTX URL list."""
        self._run_command(
            f"curl -s 'https://otx.alienvault.com/api/v1/indicators/hostname/{self.domain}/url_list?limit=500&page=1' | jq -r '.url_list[]?.result?.urlworker?.ip // empty' | grep -Eo '([0-9]{{1,3}}\.){{3}}[0-9]{{1,3}}' > {self.output_dir}/ips/otx_ips.txt",
            "AlienVault OTX IP Extraction",
            "ips/otx_ips.txt"
        )

    # URLScan.io
    def _urlscan_ip_extraction(self):
        """Extract IP addresses from URLScan.io search results."""
        self._run_command(
            f"curl -s 'https://urlscan.io/api/v1/search/?q=domain:{self.domain}&size=10000' | jq -r '.results[]?.page?.ip // empty' | grep -Eo '([0-9]{{1,3}}\.){{3}}[0-9]{{1,3}}' > {self.output_dir}/ips/urlscan_ips.txt",
            "URLScan.io IP Extraction",
            "ips/urlscan_ips.txt"
        )

    # Wayback Machine
    def _wayback_urls(self):
        """Get historical URLs from Wayback Machine."""
        self._run_command(
            f"curl -s 'https://web.archive.org/cdx/search/cdx?url={self.domain}&fl=original&collapse=urlkey' > {self.output_dir}/urls/wayback_urls.txt",
            "Wayback Machine URL Extraction",
            "urls/wayback_urls.txt"
        )

    # Shodan Search
    def _shodan_favicon_search(self):
        """Search Shodan by favicon hash (manual step)."""
        print(f"{Color.YELLOW}[*] Shodan favicon search: Use 'http.favicon.hash:1265477436' manually in Shodan{Color.RESET}")

    def _shodan_ssl_search(self):
        """Search Shodan for SSL certificates and verify HTTP responses."""
        self._run_command(
            f"shodan search 'Ssl.cert.subject.CN:\"{self.domain}\" 200' --fields ip_str | httpx -sc -title -server -td > {self.output_dir}/shodan/shodan_ssl.txt",
            "Shodan SSL Search",
            "shodan/shodan_ssl.txt"
        )

    # Nmap SSL Certificate Inspection
    def _nmap_ssl_cert(self):
        """Inspect SSL certificates on target IP using Nmap."""
        ip_file = self.output_dir / 'ips' / 'all_ips.txt'
        if not ip_file.exists() or not self.unique_ips:
            print(f"{Color.RED}[-] No IPs found for SSL inspection. Run IP extraction first.{Color.RESET}")
            return
        with open(ip_file, 'r') as f:
            ips = f.read().splitlines()
        for ip in ips[:5]:  
            self._run_command(
                f"nmap --script ssl-cert -p 443 {ip} > {self.output_dir}/ports/nmap_ssl_{ip}.txt",
                f"Nmap SSL Cert Inspection for {ip}",
                f"ports/nmap_ssl_{ip}.txt"
            )

    # Passive URL Fetching
    def _fetch_passive_urls(self):
        """Fetch passive URLs using katana."""
        self._run_command(
            f"katana -u {self.output_dir}/subdomains/subdomains_alive.txt -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -o {self.output_dir}/urls/allurls.txt",
            "Passive URL Fetching",
            "urls/allurls.txt"
        )

    # Sensitive Files
    def _find_sensitive_files(self):
        """Find sensitive files from URLs."""
        self._run_command(
            f"cat {self.output_dir}/urls/allurls.txt | grep -E '\.xls|\.xml|\.xlsx|\.json|\.pdf|\.sql|\.doc|\.docx|\.pptx|\.txt|\.zip|\.tar\.gz|\.tgz|\.bak|\.7z|\.rar|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.gz|\.config|\.csv|\.yaml|\.md|\.md5' > {self.output_dir}/sensitive_files/sensitive.txt",
            "Sensitive Files Detection",
            "sensitive_files/sensitive.txt"
        )

    # Fetch and Sort URLs
    def _fetch_sort_urls(self):
        """Fetch and sort URLs in multiple steps."""
        # Part 1
        self._run_command(
            f"echo {self.domain} | katana -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -f qurl | urldedupe > {self.output_dir}/urls/output1.txt",
            "URL Fetching Part 1",
            "urls/output1.txt"
        )
        # Part 2
        self._run_command(
            f"katana -u https://{self.domain} -d 5 | grep '=' | urldedupe | anew {self.output_dir}/urls/output1.txt",
            "URL Fetching Part 2"
        )
        # Part 3
        self._run_command(
            f"cat {self.output_dir}/urls/output1.txt | sed 's/=.*/=/' > {self.output_dir}/urls/final1.txt",
            "URL Sorting Part 3",
            "urls/final1.txt"
        )
        # Part 4
        self._run_command(
            f"echo {self.domain} | gau --mc 200 | urldedupe > {self.output_dir}/urls/urls2.txt",
            "URL Fetching Part 4",
            "urls/urls2.txt"
        )
        # Part 5
        self._run_command(
            f"cat {self.output_dir}/urls/urls2.txt | grep -E '.php|.asp|.aspx|.jspx|.jsp' | grep '=' | sort > {self.output_dir}/urls/output2.txt",
            "URL Sorting Part 5",
            "urls/output2.txt"
        )
        # Part 6
        self._run_command(
            f"cat {self.output_dir}/urls/output2.txt | sed 's/=.*/=/' > {self.output_dir}/urls/final2.txt",
            "URL Sorting Part 6",
            "urls/final2.txt"
        )

    # Hidden Parameters
    def _find_hidden_parameters(self, endpoint="endpoint.php"):
        """Find hidden parameters using Arjun."""
        url = f"https://{self.domain}/{endpoint}"
        # Part 1
        self._run_command(
            f"arjun -u {url} -oT {self.output_dir}/urls/arjun_output1.txt -t 10 --rate-limit 10 --passive -m GET,POST --headers 'User-Agent: Mozilla/5.0'",
            "Hidden Parameters Part 1",
            "urls/arjun_output1.txt"
        )
        # Part 2
        wordlist = self.config.get('wordlists', {}).get('parameters', '/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt')
        self._run_command(
            f"arjun -u {url} -oT {self.output_dir}/urls/arjun_output2.txt -m GET,POST -w {wordlist} -t 10 --rate-limit 10 --headers 'User-Agent: Mozilla/5.0'",
            "Hidden Parameters Part 2",
            "urls/arjun_output2.txt"
        )

    # CORS Checking
    def _check_cors(self):
        """Check CORS configuration."""
        url = f"https://{self.domain}/wp-json/"
        # Part 1
        self._run_command(
            f"curl -H 'Origin: http://{self.domain}' -I {url} > {self.output_dir}/cors/cors1.txt",
            "CORS Check Part 1",
            "cors/cors1.txt"
        )
        # Part 2
        self._run_command(
            f"curl -H 'Origin: http://{self.domain}' -I {url} | grep -i -e 'access-control-allow-origin' -e 'access-control-allow-methods' -e 'access-control-allow-credentials' > {self.output_dir}/cors/cors2.txt",
            "CORS Check Part 2",
            "cors/cors2.txt"
        )

    # Wordpress Scanning
    def _wordpress_scan(self):
        """Aggressive Wordpress scanning with WPScan."""
        api_token = self.api_keys.get('wpscan', '')
        if not api_token:
            print(f"{Color.RED}[-] WPScan API token not provided{Color.RESET}")
            return
        self._run_command(
            f"wpscan --url https://{self.domain} --disable-tls-checks --api-token {api_token} -e at -e ap -e u --enumerate ap --plugins-detection aggressive --force > {self.output_dir}/urls/wpscan.txt",
            "Wordpress Scanning",
            "urls/wpscan.txt"
        )

    # Directory Bruteforce
    def _directory_bruteforce(self):
        """Directory bruteforce using dirsearch and ffuf."""
        # Part 1: dirsearch
        self._run_command(
            f"dirsearch -u https://{self.domain} -e php,cgi,htm,html,shtm,shtml,js,txt,bak,zip,old,conf,log,pl,asp,aspx,jsp,sql,db,sqlite,mdb,tar,gz,7z,rar,json,xml,yml,yaml,ini,java,py,rb,php3,php4,php5 --random-agent --recursive -R 3 -t 20 --exclude-status=404 --follow-redirects --delay=0.1 > {self.output_dir}/dir_brute/dirsearch.txt",
            "Directory Bruteforce Part 1",
            "dir_brute/dirsearch.txt"
        )
        # Part 2: ffuf
        wordlist = self.config.get('wordlists', {}).get('dir', '/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt')
        self._run_command(
            f"ffuf -w {wordlist} -u https://{self.domain}/FUZZ -fc 400,401,402,403,404,429,500,501,502,503 -recursion -recursion-depth 2 -e .html,.php,.txt,.pdf,.js,.css,.zip,.bak,.old,.log,.json,.xml,.config,.env,.asp,.aspx,.jsp,.gz,.tar,.sql,.db -ac -c -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0' -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Originating-IP: 127.0.0.1' -H 'X-Forwarded-Host: localhost' -t 100 -r -o {self.output_dir}/dir_brute/ffuf.json",
            "Directory Bruteforce Part 2",
            "dir_brute/ffuf.json"
        )

    # JS File Hunting
    def _js_file_hunting(self):
        """Hunt for JS files and check exposures."""
        # Part 1
        self._run_command(
            f"echo {self.domain} | katana -d 5 | grep -E '\.js$' | nuclei -t nuclei-templates/http/exposures/ -c 30 > {self.output_dir}/js_files/js_exposures1.txt",
            "JS File Hunting Part 1",
            "js_files/js_exposures1.txt"
        )
        # Part 2
        self._run_command(
            f"cat {self.output_dir}/urls/allurls.txt | grep -E '\.js$' | nuclei -t /home/tuhamesec/nuclei-templates/http/exposures/ > {self.output_dir}/js_files/js_exposures2.txt",
            "JS File Hunting Part 2",
            "js_files/js_exposures2.txt"
        )

    # Subdomain Takeover
    def _check_subdomain_takeover(self):
        """Check for subdomain takeover using subzy."""
        self._run_command(
            f"subzy run --targets {self.output_dir}/subdomains/subdomains.txt --concurrency 100 --hide_fails --verify_ssl > {self.output_dir}/subdomains/takeover.txt",
            "Subdomain Takeover Check",
            "subdomains/takeover.txt"
        )

    # Network Scanning
    def _network_scanning(self):
        """Perform network scanning with naabu, nmap, and masscan."""
        # Naabu
        self._run_command(
            f"naabu -list {self.output_dir}/subdomains/subdomains_alive.txt -c 50 -nmap-cli 'nmap -sV -SC' -o {self.output_dir}/ports/naabu-full.txt",
            "Naabu Scan",
            "ports/naabu-full.txt"
        )
        # Nmap
        self._run_command(
            f"nmap -p- --min-rate 1000 -T4 -A {self.domain} -oA {self.output_dir}/ports/fullscan",
            "Nmap Scan",
            "ports/fullscan"
        )
        # Masscan
        self._run_command(
            f"masscan -p0-65535 {self.domain} --rate 100000 -oG {self.output_dir}/ports/masscan-results.txt",
            "Masscan Scan",
            "ports/masscan-results.txt"
        )

    def _process_ips(self):
        """Process and deduplicate IP addresses."""
        all_ips = []
        for file in (self.output_dir / 'ips').glob('*.txt'):
            with open(file) as f:
                all_ips.extend(f.read().splitlines())
        
        cleaned = {ip.strip() for ip in all_ips if ip.strip() and re.match(r'([0-9]{1,3}\.){3}[0-9]{1,3}', ip)}
        with open(self.output_dir / 'ips' / 'all_ips.txt', 'w') as f:
            f.write('\n'.join(sorted(cleaned)))
        
        self.unique_ips = cleaned
        print(f"{Color.GREEN}[+] Total unique IPs: {len(self.unique_ips)}{Color.RESET}")

    def _github_api_search_code(self, token, search, page, sort, order, verbose=False):
        """Search GitHub code using the GitHub API."""
        headers = {"Authorization": "token " + token}
        url = f'https://api.github.com/search/code?per_page=100&s={sort}&type=Code&o={order}&q={search}&page={str(page)}'
        if verbose:
            print(f">>> {url}")
        try:
            r = requests.get(url, headers=headers, timeout=5)
            json_data = r.json()
            return json_data
        except Exception as e:
            print(f"[-] error occurred: {e}")
            return False

    def _get_raw_url(self, result):
        """Get the raw URL from GitHub search results."""
        raw_url = result['html_url'].replace('https://github.com/', 'https://raw.githubusercontent.com/').replace('/blob/', '/')
        return raw_url

    def _do_get_code(self, url):
        """Fetch code from a raw URL."""
        try:
            r = requests.get(url, timeout=5)
            return r.text
        except Exception as e:
            print(f"[-] error occurred: {e}")
            return False

    def _read_code(self, domain_regexp, source, result):
        """Read code from GitHub and extract subdomains."""
        time.sleep(random.random())
        url = self._get_raw_url(result)
        if url in self.t_history_urls:
            return
        output = ''
        self.t_history_urls.append(url)
        code = self._do_get_code(url)
        t_local_history = []

        if code:
            matches = re.findall(domain_regexp, code, re.IGNORECASE)
            if matches:
                for sub in matches:
                    sub = sub[0].replace('2F', '').lower().strip()
                    if len(sub) and sub not in t_local_history:
                        t_local_history.append(sub)
                        if source:
                            if not len(output):
                                output += f">>> {result['html_url']}\n\n"
                            self.t_history.append(sub)
                            output += f"{sub}\n"
                        elif sub not in self.t_history:
                            self.t_history.append(sub)
                            output += f"{sub}\n"
        if len(output.strip()):
            with open(self.output_dir / 'github' / 'github_subdomains.txt', 'a') as f:
                f.write(f"{output.strip()}\n")

    def _github_search(self, extend=False, source=False, verbose=False):
        """GitHub search for subdomains."""
        if not self.github_tokens:
            print(f"{Color.RED}[-] No GitHub tokens provided. Skipping GitHub search.{Color.RESET}")
            return

        t_sort_order = [
            {'sort': 'indexed', 'order': 'desc'},
            {'sort': 'indexed', 'order': 'asc'},
            {'sort': '', 'order': 'desc'}
        ]

        t_host_parse = tldextract.extract(self.domain)
        search = f'"{t_host_parse.domain}.{t_host_parse.suffix}"'
        if extend:
            search = f'"{t_host_parse.domain}"'
        search = search.replace('-', '%2D')

        domain_regexp = r'(([0-9a-z_\-\.]+)\.' + self.domain.replace('.', '\.') + ')'
        if extend:
            domain_regexp = r'([0-9a-z_\-\.]+\.([0-9a-z_\-]+)?' + t_host_parse.domain + '([0-9a-z_\-\.]+)?\.[a-z]{1,5})'

        if verbose:
            print(f"Search: {search}")
            print(f"Regexp: {domain_regexp}")

        for so in t_sort_order:
            page = 1
            if verbose:
                print(f'\n----- {so["sort"]} {so["order"]}\n')

            while True:
                if verbose:
                    print(f"page {page}")
                token = random.choice(self.github_tokens)
                t_json = self._github_api_search_code(token, search, page, so['sort'], so['order'], verbose)

                if not t_json or 'documentation_url' in t_json or 'message' in t_json:
                    if verbose:
                        print(t_json)
                    self.github_tokens.remove(token)
                    if not self.github_tokens:
                        print(f"{Color.RED}[-] No valid GitHub tokens remaining.{Color.RESET}")
                        return
                    continue

                page += 1
                if 'items' in t_json and len(t_json['items']):
                    pool = Pool(30)
                    pool.map(partial(self._read_code, domain_regexp, source), t_json['items'])
                    pool.close()
                    pool.join()
                else:
                    break

    def passive_enumeration(self):
        """Passive enumeration."""
        print(f"{Color.CYAN}[*] Starting passive enumeration...{Color.RESET}")
        self._subfinder()
        self._filter_live_subdomains()
        self._virustotal_report()
        self._alienvault_ip_extraction()
        self._urlscan_ip_extraction()
        self._github_search(extend=False, source=True, verbose=False) 
        self._wayback_urls()
        self._fetch_passive_urls()
        self._find_sensitive_files()
        self._fetch_sort_urls()
        self._process_subdomains()
        self._process_ips()

    def active_enumeration(self):
        """Active enumeration."""
        print(f"{Color.CYAN}[*] Starting active enumeration...{Color.RESET}")
        self._find_hidden_parameters()
        self._check_cors()
        self._wordpress_scan()
        self._lfi_testing()
        self._directory_bruteforce()
        self._js_file_hunting()
        self._check_subdomain_takeover()
        self._xss_testing()
        self._shodan_ssl_search()
        self._nmap_ssl_cert()
        self._network_scanning()
        self._process_subdomains()
        self._process_ips()

    def _process_subdomains(self):
        """Process and deduplicate subdomains."""
        all_subs = []
        for file in (self.output_dir / 'subdomains').glob('*.txt'):
            with open(file) as f:
                all_subs.extend(f.read().splitlines())
        
        cleaned = {s.lower().strip() for s in all_subs if s.strip()}
        with open(self.output_dir / 'subdomains' / 'final_subs.txt', 'w') as f:
            f.write('\n'.join(sorted(cleaned)))
        
        self.unique_subdomains = cleaned
        print(f"{Color.GREEN}[+] Total unique subdomains: {len(self.unique_subdomains)}{Color.RESET}")

def load_config(config_file):
    """Load configuration from a JSON file."""
    if not config_file or not Path(config_file).exists():
        return {}
    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"{Color.RED}[-] Error loading config file: {e}{Color.RESET}")
        return {}
        
def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="Advanced OSINT Toolkit for Reconnaissance")
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument("-o", "--output-dir", default="./output", help="Output directory (default: ./output)")
    parser.add_argument("--active", action="store_true", help="Enable active enumeration")
    parser.add_argument("--brute", action="store_true", help="Enable brute force enumeration")
    parser.add_argument("--config", help="Path to configuration file (JSON)")
    parser.add_argument("--vt-key", help="VirusTotal API key")
    parser.add_argument("--av-key", help="AlienVault API key")
    parser.add_argument("--wpscan-key", help="WPScan API key")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()

    # Load configuration from file if provided
    config = load_config(args.config)

    # Override config with command-line arguments if provided
    api_keys = {
        'virustotal': args.vt_key or config.get('api_keys', {}).get('virustotal', ''),
        'alienvault': args.av_key or config.get('api_keys', {}).get('alienvault', ''),
        'wpscan': args.wpscan_key or config.get('api_keys', {}).get('wpscan', '')
    }

    # Use default wordlists from config if not overridden
    if 'wordlists' not in config:
        config['wordlists'] = {
            'resolvers': '/path/to/resolvers.txt',
            'dns': '/path/to/dns_wordlist.txt',
            'lfi': '/path/to/lfi_payloads.txt',
            'dir': '/path/to/dir_wordlist.txt',
            'parameters': '/usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt'
        }

    try:
        toolkit = OSINTToolkit(
            domain=args.domain,
            config=config,
            api_keys=api_keys,
            output_dir=args.output_dir,
            active=args.active,
            brute=args.brute
        )
        toolkit.passive_enumeration()
        if args.active:
            toolkit.active_enumeration()
    except ValueError as e:
        print(f"{Color.RED}[-] Error: {e}{Color.RESET}")
    except FileNotFoundError as e:
        print(f"{Color.RED}[-] Error: {e}{Color.RESET}")
