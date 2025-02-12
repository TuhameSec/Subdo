import os
import sys
import json
import argparse
import subprocess
from threading import Thread
from queue import Queue
from time import sleep
from pathlib import Path
from getpass import getpass


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
    def __init__(self, domain, config=None, api_keys=None):
        self.domain = domain
        self.config = config or CONFIG
        self.api_keys = api_keys or {}
        self.output_dir = Path(self.config['output_dir'])
        self._setup_directories()
        
    def _setup_directories(self):
        self.output_dir.mkdir(exist_ok=True)
        (self.output_dir/'subdomains').mkdir(exist_ok=True)
        (self.output_dir/'ports').mkdir(exist_ok=True)
        (self.output_dir/'urls').mkdir(exist_ok=True)

    def _run_command(self, command, tool_name, output_file=None):
        try:
            result = subprocess.run(
                command,
                shell=True,
                check=True,
                capture_output=True,
                text=True
            )
            output = result.stdout.strip()
            
            if output_file:
                with open(self.output_dir/output_file, 'w') as f:
                    f.write(output)
            
            print(f"{Color.GREEN}[+] {tool_name} completed successfully{Color.END}")
            return output
            
        except subprocess.CalledProcessError as e:
            print(f"{Color.RED}[-] Error in {tool_name}: {e.stderr}{Color.END}")
            return None

    def passive_enumeration(self):
        print(f"\n{Color.BLUE}[*] Starting Passive Enumeration{Color.END}")
        
        # Subfinder
        self._run_command(
            f"{self.config['tools_path']['subfinder']} -d {self.domain} -all -silent",
            "Subfinder",
            "subdomains/subfinder.txt"
        )
        
        # Censys.io
        if self.api_keys.get('censys'):
            censys_cmd = f"""
            curl -s -X POST \
            -H 'Authorization: Basic {self.api_keys["censys"]}' \
            -H 'Content-Type: application/json' \
            -d '{{"query": "{self.domain}", "fields": ["parsed.names"]}}' \
            https://censys.io/api/v1/search/certificates | \
            grep -Po '[\w\.]+{self.domain}' | \
            sed 's/^www\.//g; s/^\.//g' | \
            sort -u
            """
            self._run_command(censys_cmd, "Censys", "subdomains/censys.txt")

    def active_enumeration(self):
        print(f"\n{Color.BLUE}[*] Starting Active Enumeration{Color.END}")
        
        # Massdns
        massdns_cmd = f"""
        awk -v host="{self.domain}" '{{print $0"."host}}' {self.config['wordlists']['dns']} > massdns.list && \
        {self.config['tools_path']['massdns']} -r {self.config['wordlists']['resolvers']} \
        -t A -o S massdns.list -w {self.output_dir}/subdomains/massdns.txt
        """
        self._run_command(massdns_cmd, "Massdns")

    def port_scanning(self):
        print(f"\n{Color.BLUE}[*] Starting Port Scanning{Color.END}")
        
        # Generate IP list
        self._run_command(
            f"cat {self.output_dir}/subdomains/*.txt | xargs dig +short | grep -Po '\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}' > {self.output_dir}/ports/ips.txt",
            "IP Collection"
        )
        
        # Masscan
        masscan_cmd = f"""
        masscan -p0-65535 --rate=10000 -iL {self.output_dir}/ports/ips.txt \
        -oJ {self.output_dir}/ports/masscan.json
        """
        self._run_command(masscan_cmd, "Masscan")

    def url_enumeration(self):
        print(f"\n{Color.BLUE}[*] Starting URL Enumeration{Color.END}")
        
        # Waybackurls
        self._run_command(
            f"cat {self.output_dir}/subdomains/*.txt | {self.config['tools_path']['waybackurls']} | sort -u > {self.output_dir}/urls/wayback.txt",
            "Waybackurls"
        )
        
        # GAU
        self._run_command(
            f"{self.config['tools_path']['gau']} {self.domain} | sort -u > {self.output_dir}/urls/gau.txt",
            "GAU"
        )

def check_dependencies():
    required_tools = ['subfinder', 'massdns', 'httpx']
    missing = []
    for tool in required_tools:
        if not Path(CONFIG['tools_path'].get(tool, '')).exists():
            missing.append(tool)
    if missing:
        print(f"{Color.RED}[-] Missing dependencies: {', '.join(missing)}{Color.END}")
        sys.exit(1)

def load_config(config_file):
    try:
        with open(config_file) as f:
            return json.load(f)
    except Exception as e:
        print(f"{Color.RED}[-] Error loading config: {e}{Color.END}")
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
    enumerator = SubdomainEnumerator(
        domain=args.domain,
        config=config,
        api_keys=api_keys
    )
    
    # Execute enumeration phases
    enumerator.passive_enumeration()
    enumerator.active_enumeration()
    enumerator.port_scanning()
    enumerator.url_enumeration()
    
    print(f"\n{Color.GREEN}[+] All operations completed! Results saved to {enumerator.output_dir}{Color.END}")

if __name__ == "__main__":
    main()