import os
import requests
import sys
import re
import dns.resolver
import json
import argparse
import subprocess
from threading import Thread
from queue import Queue
from time import sleep
from pathlib import Path
from getpass import getpass
from concurrent.futures import ThreadPoolExecutor  # Added missing import

class Color:
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
    
print(f'''
{Color.CYAN}
███████╗██╗   ██╗██████╗ ██████╗  ██████╗ 
██╔════╝██║   ██║██╔══██╗██╔══██╗██╔═══██╗
███████╗██║   ██║██████╔╝██║  ██║██║   ██║
╚════██║██║   ██║██╔══██╗██║  ██║██║   ██║
███████║╚██████╔╝██████╔╝██████╔╝╚██████╔╝
╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝
{Color.RESET}
[{Color.RED}~{Color.RESET}] {Color.ORANGE}Version:{Color.RESET} 1.0
[{Color.RED}~{Color.RESET}] {Color.ORANGE}Description:{Color.RESET} Advanced Subdomain Enumeration Toolkit
''')

CONFIG = {
    "tools_path": {
        "subfinder": "/usr/local/bin/subfinder",
        "assetfinder": "/usr/local/bin/assetfinder",
        "knockpy": "/usr/local/bin/knockpy",
        "findomain": "/usr/local/bin/findomain",
        "massdns": "/usr/local/bin/massdns",
        "httpx": "/usr/local/bin/httpx",
        "waybackurls": "/usr/local/bin/waybackurls",
        "gau": "/usr/local/bin/gau"
    },
    "wordlists": {
        "dns": "/opt/wordlists/dns.txt",
        "resolvers": "/opt/wordlists/resolvers.txt"
    },
    "output_dir": "results"
}


class SubdomainEnumerator:
    def __init__(self, domain, config, api_keys):
        self.domain = domain
        self.config = config
        self.api_keys = api_keys
        self.output_dir = Path(self.config.get('output_dir', 'results'))
        self.resolvers = self._load_resolvers()
        self.wordlists = self._load_wordlists()
        self._create_output_dir()

    def _load_resolvers(self):
        """Load DNS resolvers from file"""
        resolvers_file = self.config.get('wordlists', {}).get('resolvers', '')
        if resolvers_file and Path(resolvers_file).exists():
            with open(resolvers_file) as f:
                return [line.strip() for line in f if line.strip()]
        return ['1.1.1.1', '8.8.8.8', '9.9.9.9']  # Default resolvers

    def _load_wordlists(self):
        """Load DNS wordlist"""
        dns_wordlist = self.config.get('wordlists', {}).get('dns', '')
        if dns_wordlist and Path(dns_wordlist).exists():
            return Path(dns_wordlist)
        raise FileNotFoundError(f"DNS wordlist not found at {dns_wordlist}")

    def _create_output_dir(self):
        """Create output directory structure"""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / 'subdomains').mkdir(exist_ok=True)
        (self.output_dir / 'ports').mkdir(exist_ok=True)
        (self.output_dir / 'urls').mkdir(exist_ok=True)

    def _run_command(self, command, task_name, output_file=None):
        """Execute shell command and handle output"""
        print(f"{Color.GREEN}[+] Running {task_name}...{Color.RESET}")
        try:
            result = subprocess.run(command, shell=True, check=True, 
                                   capture_output=True, text=True)
            if output_file:
                output_path = self.output_dir / output_file
                with open(output_path, 'w') as f:
                    f.write(result.stdout)
            print(f"{Color.GREEN}[+] {task_name} completed.{Color.RESET}")
        except subprocess.CalledProcessError as e:
            print(f"{Color.RED}[-] Error in {task_name}: {e}{Color.RESET}")

    def passive_enumeration(self):
        """Base passive enumeration method"""
        pass

    def active_enumeration(self):
        """Base active enumeration method"""
        pass

    def port_scanning(self):
        """Base port scanning method"""
        pass

    def url_enumeration(self):
        """Base URL enumeration method"""
        pass

class EnhancedSubdomainEnumerator(SubdomainEnumerator):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = self.resolvers
        self.unique_subdomains = set()
        self.valid_ports = {}

    def _validate_domain(self):
        """Validate domain format"""
        domain_regex = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
        if not re.match(domain_regex, self.domain):
            raise ValueError(f"Invalid domain format: {self.domain}")

    def _resolve_dns(self, subdomain):
        """Resolve DNS records"""
        try:
            answers = self.resolver.resolve(subdomain, 'A')
            return [str(r) for r in answers]
        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.NXDOMAIN:
            return []
        except Exception as e:
            print(f"{Color.RED}DNS Error: {e}{Color.RESET}")
            return []

    def _process_subdomains(self):
        """Process and deduplicate subdomains"""
        all_subs = []
        for file in (self.output_dir/'subdomains').glob('*.txt'):
            with open(file) as f:
                all_subs.extend(f.read().splitlines())
        
        cleaned = {s.lower().strip() for s in all_subs if s.strip()}
        with open(self.output_dir/'subdomains'/'final_subs.txt', 'w') as f:
            f.write('\n'.join(sorted(cleaned)))
        
        self.unique_subdomains = cleaned

    def passive_enumeration(self):
        super().passive_enumeration()
        
        # GitHub Subdomains
        if self.api_keys.get('github'):
            self._run_command(
                f"python3 github-subdomains.py -t {self.api_keys['github']} -d {self.domain} | "
                f"grep -v '@' | sort -u | grep '\\.{self.domain}$'",
                "GitHub Subdomains",
                "subdomains/github.txt"
            )
        
        # Additional sources
        self._amass_enumeration()
        self._certspotter()
        self._bufferover()
        
        self._process_subdomains()

    def _amass_enumeration(self):
        """Run Amass enumeration"""
        self._run_command(
            f"amass enum -passive -d {self.domain} -silent",
            "Amass",
            "subdomains/amass.txt"
        )

    def _certspotter(self):
        """Query Cert Spotter API"""
        try:
            url = f"https://certspotter.com/api/v0/certs?domain={self.domain}"
            response = requests.get(url, timeout=10)
            data = response.json()
            subs = set()
            for cert in data:
                subs.update(cert['dns_names'])
            with open(self.output_dir/'subdomains'/'certspotter.txt', 'w') as f:
                f.write('\n'.join(filter(lambda x: x.endswith(self.domain), subs)))
        except Exception as e:
            print(f"{Color.RED}Certspotter Error: {e}{Color.RESET}")

    def _bufferover(self):
        """Query BufferOver API"""
        try:
            response = requests.get(f"https://dns.bufferover.run/dns?q=.{self.domain}", 
                                  timeout=10)
            data = response.json()
            subs = set()
            for record in data.get('FDNS_A', []):
                subs.add(record.split(',')[-1])
            with open(self.output_dir/'subdomains'/'bufferover.txt', 'w') as f:
                f.write('\n'.join(filter(lambda x: x.endswith(self.domain), subs)))
        except Exception as e:
            print(f"{Color.RED}BufferOver Error: {e}{Color.RESET}")

    def active_enumeration(self):
        super().active_enumeration()
        self._massdns_validation()
        self._altdns_permutation()

    def _massdns_validation(self):
        """Validate subdomains with multiple resolvers"""
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(self._resolve_dns, sub): sub 
                     for sub in self.unique_subdomains}
            for future in futures:
                sub = futures[future]
                ips = future.result()
                if ips:
                    print(f"{Color.GREEN}Valid: {sub} → {', '.join(ips)}{Color.RESET}")
                else:
                    print(f"{Color.RED}Invalid: {sub}{Color.RESET}")

    def _altdns_permutation(self):
        """Generate subdomain permutations"""
        self._run_command(
            f"altdns -i {self.output_dir}/subdomains/final_subs.txt "
            f"-w ~/wordlists/altdns_words.txt -o {self.output_dir}/subdomains/altdns.txt",
            "AltDNS Permutations"
        )

    def port_scanning(self):
        super().port_scanning()
        self._service_detection()
        self._vulnerability_checks()

    def _service_detection(self):
        """Perform service detection with Nmap"""
        self._run_command(
            f"nmap -sV -iL {self.output_dir}/ports/ips.txt "
            f"-oG {self.output_dir}/ports/nmap_services.txt",
            "Nmap Service Detection"
        )

    def _vulnerability_checks(self):
        """Run basic vulnerability scans"""
        self._run_command(
            f"nuclei -t ~/nuclei-templates/ -l {self.output_dir}/ports/open_ports.txt",
            "Nuclei Vulnerability Scan"
        )

    def url_enumeration(self):
        super().url_enumeration()
        self._param_spider()
        self._js_endpoints()

    def _param_spider(self):
        """Find URL parameters"""
        self._run_command(
            f"python3 paramspider.py -d {self.domain} --exclude png,jpg,gif",
            "ParamSpider",
            "urls/params.txt"
        )

    def _js_endpoints(self):
        """Extract JavaScript endpoints"""
        self._run_command(
            f"katana -u {self.output_dir}/urls/wayback.txt "
            f"-jc -kf -d 3 -o {self.output_dir}/urls/js_endpoints.txt",
            "JavaScript Endpoints"
        )

def check_dependencies():
    required_tools = ['subfinder', 'massdns', 'httpx']
    missing = []
    for tool in required_tools:
        if not Path(CONFIG['tools_path'].get(tool, '')).exists():
            missing.append(tool)
    if missing:
        print(f"{Color.RED}[-] Missing dependencies: {', '.join(missing)}{Color.RESET}")
        sys.exit(1)

def load_config(config_file):
    try:
        with open(config_file) as f:
            return json.load(f)
    except Exception as e:
        print(f"{Color.RED}[-] Error loading config: {e}{Color.RESET}")
        return CONFIG

def main():
    parser = argparse.ArgumentParser(description="Advanced Subdomain Enumeration Toolkit")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-c", "--config", help="Custom config file")
    parser.add_argument("-o", "--output", help="Output directory")
    args = parser.parse_args()

    check_dependencies()
    
    # Load configuration
    config = load_config(args.config) if args.config else CONFIG
    
    # Get API keys securely
    api_keys = {
        'censys': getpass("Enter Censys API Key (optional): "),
        'github': getpass("Enter GitHub Token (optional): ")
    }
    
    # Initialize enumerator
    enumerator = EnhancedSubdomainEnumerator(  # Changed to Enhanced class
        domain=args.domain,
        config=config,
        api_keys=api_keys
    )
    
    # Execute enumeration phases
    enumerator.passive_enumeration()
    enumerator.active_enumeration()
    enumerator.port_scanning()
    enumerator.url_enumeration()
    
    print(f"\n{Color.GREEN}[+] All operations completed! Results saved to {enumerator.output_dir}{Color.RESET}")

if __name__ == "__main__":
    main()