import os
import re
import sys
import json
import asyncio
import logging
import argparse
import subprocess
from pathlib import Path
from typing import Dict, List, Set, Optional, Callable, Any
from dataclasses import dataclass
from uuid import uuid4
import aiofiles
import aiohttp
from aiohttp import ClientSession
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from jsonschema import validate, ValidationError
from contextlib import asynccontextmanager
import tldextract
import tenacity
from tenacity import retry, stop_after_attempt, wait_exponential
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
from rich.panel import Panel
from tabulate import tabulate
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import shodan
import random

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("osint_toolkit.log")
    ]
)
logger = logging.getLogger(__name__)

# Initialize rich console
console = Console()

@dataclass
class ToolConfig:
    name: str
    command: str
    installed: bool = False
    version_check: Optional[str] = None
    fallback: Optional[str] = None
    required: bool = True
    output_validator: Optional[Callable[[str], bool]] = None

@dataclass
class UrlFetcherConfig:
    katana: Dict[str, Any]
    gau: Dict[str, Any]
    js_filters: Dict[str, Any]

@dataclass
class GoogleDorkConfig:
    enabled: bool
    api_key: str
    cse_id: str
    queries: Dict[str, List[str]]
    proxy_pool: List[str]
    max_results: int

@dataclass
class ShodanConfig:
    enabled: bool
    api_key: str

@dataclass
class TheHarvesterConfig:
    enabled: bool
    sources: List[str]

@dataclass
class GitHubConfig:
    enabled: bool
    api_key: str
    search_terms: List[str]

@dataclass
class Config:
    wordlists: Dict[str, str]
    api_keys: Dict[str, str]
    tools: Dict[str, ToolConfig]
    cdx_api: Dict[str, Any]
    url_fetcher: UrlFetcherConfig
    google_dorks: GoogleDorkConfig
    shodan: ShodanConfig
    the_harvester: TheHarvesterConfig
    github: GitHubConfig
    output_formats: List[str] = None
    max_retries: int = 3
    rate_limit: float = 1.0
    timeout: int = 10
    max_concurrent: int = 10

    def __post_init__(self):
        if self.cdx_api is None:
            self.cdx_api = {
                "enabled": True,
                "base_url": "https://web.archive.org/cdx/search/cdx",
                "params": {
                    "output": "text",
                    "fl": "original",
                    "limit": 10000
                }
            }
        if self.url_fetcher is None:
            self.url_fetcher = UrlFetcherConfig(
                katana={
                    "depth": 5,
                    "sources": ["waybackarchive", "commoncrawl", "alienvault"],
                    "exclude_extensions": ["woff", "css", "png", "svg", "jpg", "woff2", "jpeg", "gif"],
                    "flags": ["-kf", "-jc", "-fx"]
                },
                gau={
                    "status_codes": [200],
                    "file_extensions": ["php", "asp", "aspx", "jspx", "jsp"]
                },
                js_filters={
                    "content_types": ["application/javascript", "text/javascript"],
                    "sensitive_patterns": ["API_KEY", "api_key", "apikey", "secret", "token", "password"]
                }
            )
        if self.google_dorks is None:
            self.google_dorks = GoogleDorkConfig(
                enabled=True,
                api_key="",
                cse_id="",
                queries={
                    "basic_recon": [
                        "site:{domain} -www -shop -share -ir -mfa",
                        "site:{domain} ext:php inurl:?",
                        "site:{domain} inurl:api | site:*/rest | site:*/v1 | site:*/v2 | site:*/v3"
                    ],
                    "sensitive_files": [
                        "site:'{domain}' ext:log | ext:txt | ext:conf | ext:cnf | ext:ini | ext:env | ext:sh | ext:bak | ext:backup | ext:swp | ext:old | ext:~ | ext:git | ext:svn | ext:htpasswd | ext:htaccess | ext:json",
                        "inurl:conf | inurl:env | inurl:cgi | inurl:bin | inurl:etc | inurl:root | inurl:sql | inurl:backup | inurl:admin | inurl:php site:{domain}"
                    ],
                    "error_pages": [
                        "inurl:'error' | intitle:'exception' | intitle:'failure' | intitle:'server at' | inurl:exception | 'database error' | 'SQL syntax' | 'undefined index' | 'unhandled exception' | 'stack trace' site:{domain}"
                    ],
                    "vulnerable_params": [
                        "inurl:q= | inurl:s= | inurl:search= | inurl:query= | inurl:keyword= | inurl:lang= inurl:& site:{domain}",
                        "inurl:url= | inurl:return= | inurl:next= | inurl:redirect= | inurl:redir= | inurl:ret= | inurl:r2= | inurl:page= inurl:& inurl:http site:{domain}",
                        "inurl:id= | inurl:pid= | inurl:category= | inurl:cat= | inurl:action= | inurl:sid= | inurl:dir= inurl:& site:{domain}",
                        "inurl:http | inurl:url= | inurl:path= | inurl:dest= | inurl:html= | inurl:data= | inurl:domain= | inurl:page= inurl:& site:{domain}",
                        "inurl:include | inurl:dir | inurl:detail= | inurl:file= | inurl:folder= | inurl:inc= | inurl:locate= | inurl:doc= | inurl:conf= inurl:& site:{domain}",
                        "inurl:cmd | inurl:exec= | inurl:query= | inurl:code= | inurl:do= | inurl:run= | inurl:read= | inurl:ping= inurl:& site:{domain}"
                    ],
                    "cloud_storage": [
                        "site:s3.amazonaws.com '{domain}'",
                        "site:blob.core.windows.net '{domain}'",
                        "site:googleapis.com '{domain}'",
                        "site:drive.google.com '{domain}'",
                        "site:dev.azure.com '{domain}'",
                        "site:onedrive.live.com '{domain}'",
                        "site:digitaloceanspaces.com '{domain}'",
                        "site:sharepoint.com '{domain}'",
                        "site:s3-external-1.amazonaws.com '{domain}'",
                        "site:s3.dualstack.us-east-1.amazonaws.com '{domain}'",
                        "site:dropbox.com/s '{domain}'",
                        "site:box.com/s '{domain}'",
                        "site:docs.google.com inurl:'/d/' '{domain}'",
                        "site:jfrog.io '{domain}'",
                        "site:firebaseio.com '{domain}'"
                    ],
                    "code_docs": [
                        "site:pastebin.com '{domain}'",
                        "site:jsfiddle.net '{domain}'",
                        "site:codebeautify.org '{domain}'",
                        "site:codepen.io '{domain}'",
                        "inurl:apidocs | inurl:api-docs | inurl:swagger | inurl:api-explorer site:'{domain}'",
                        "site:openbugbounty.org inurl:reports intext:'{domain}'",
                        "site:groups.google.com '{domain}'"
                    ],
                    "sensitive_content": [
                        "site:{domain} 'choose file'",
                        "inurl:login | inurl:signin | intitle:login | intitle:signin | inurl:secure site:{domain}",
                        "inurl:test | inurl:env | inurl:dev | inurl:staging | inurl:sandbox | inurl:debug | inurl:temp | inurl:internal | inurl:demo site:{domain}",
                        "site:{domain} ext:txt | ext:pdf | ext:xml | ext:xls | ext:xlsx | ext:ppt | ext:pptx | ext:doc | ext:docx",
                        "intext:'confidential' | intext:'Not for Public Release' | intext:'internal use only' | intext:'do not distribute' site:{domain}",
                        "inurl:email= | inurl:phone= | inurl:password= | inurl:secret= inurl:& site:{domain}"
                    ]
                },
                proxy_pool=["http://proxy1:8080", "http://proxy2:8080"],
                max_results=100
            )
        if self.shodan is None:
            self.shodan = ShodanConfig(
                enabled=True,
                api_key=""
            )
        if self.the_harvester is None:
            self.the_harvester = TheHarvesterConfig(
                enabled=True,
                sources=["bing", "google", "linkedin", "twitter"]
            )
        if self.github is None:
            self.github = GitHubConfig(
                enabled=True,
                api_key="",
                search_terms=["{domain} api_key", "{domain} secret", "{domain} password"]
            )
        if self.output_formats is None:
            self.output_formats = ["json", "markdown", "csv"]

@dataclass
class OSINTToolkitState:
    unique_subdomains: Set[str]
    unique_ips: Set[str]
    t_history: List[str]
    t_history_urls: List[str]
    tool_status: Dict[str, bool]
    dork_results: Dict[str, List[str]]
    emails: Set[str]
    social_media: Dict[str, List[str]]
    github_results: List[str]
    shodan_results: List[Dict[str, Any]]

class GoogleDorkScanner:
    def __init__(self, config: GoogleDorkConfig, domain: str, output_dir: Path, session: ClientSession):
        self.config = config
        self.domain = domain
        self.output_dir = output_dir / "dorks"
        self.session = session
        self.results: Dict[str, List[str]] = {category: [] for category in config.queries.keys()}
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.seen_urls: Set[str] = set()

    def _validate_dork(self, query: str) -> bool:
        """Validate Google dork syntax."""
        try:
            formatted_query = query.format(domain=self.domain)
            return bool(formatted_query.strip()) and not re.search(r'[<>]', formatted_query)
        except Exception:
            return False

    async def run_dork_scan(self) -> Dict[str, List[str]]:
        if not self.config.enabled:
            console.print("[yellow]⚠ Google dork scanning disabled in config. Skipping.[/yellow]")
            return self.results

        console.print("[cyan]▶ Starting Google dork scanning...[/cyan]")
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeRemainingColumn(),
            console=console
        ) as progress:
            total_queries = sum(len(queries) for queries in self.config.queries.values())
            task_id = progress.add_task("Google Dork Scanning", total=total_queries)

            for category, queries in self.config.queries.items():
                for query in queries:
                    if not self._validate_dork(query):
                        console.print(f"[red]✖ Invalid dork in {category}: '{query}'[/red]")
                        continue
                    formatted_query = query.format(domain=self.domain)
                    try:
                        if self.config.api_key and self.config.cse_id:
                            results = await self._search_with_api(formatted_query)
                        else:
                            results = await self._search_with_scraping(formatted_query)
                        unique_results = [url for url in results if url not in self.seen_urls]
                        self.seen_urls.update(unique_results)
                        self.results[category].extend(unique_results)
                        async with aiofiles.open(
                            self.output_dir / f"{category}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt", 'w'
                        ) as f:
                            await f.write('\n'.join(unique_results))
                        console.print(f"[green]✔ {category}: {len(unique_results)} results for '{formatted_query}'[/green]")
                    except Exception as e:
                        console.print(f"[red]✖ Error in {category} query '{formatted_query}': {e}[/red]")
                    progress.advance(task_id)
                    await asyncio.sleep(self.config.rate_limit)

        return self.results

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
    async def _search_with_api(self, query: str, start: int = 1) -> List[str]:
        try:
            service = build("customsearch", "v1", developerKey=self.config.api_key)
            result = service.cse().list(q=query, cx=self.config.cse_id, num=10, start=start).execute()
            items = result.get("items", [])
            urls = [item["link"] for item in items if self._is_valid_url(item["link"])]
            if start < self.config.max_results and "nextPage" in result.get("queries", {}):
                urls.extend(await self._search_with_api(query, start + 10))
            return urls
        except HttpError as e:
            console.print(f"[red]✖ Google API error: {e}[/red]")
            return []

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
    async def _search_with_scraping(self, query: str) -> List[str]:
        headers = {
            "User-Agent": random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"
            ])
        }
        proxy = random.choice(self.config.proxy_pool) if self.config.proxy_pool else None
        url = f"https://www.google.com/search?q={query.replace(' ', '+')}&num=10"
        try:
            async with self.session.get(url, headers=headers, proxy=proxy) as response:
                if response.status != 200:
                    console.print(f"[red]✖ Google scraping failed: {response.status}[/red]")
                    return []
                text = await response.text()
                urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', text)
                return [url for url in urls if self._is_valid_url(url) and self.domain in url]
        except Exception as e:
            console.print(f"[red]✖ Scraping error: {e}[/red]")
            return []

    def _is_valid_url(self, url: str) -> bool:
        pattern = r'^https?://[^\s/$.?#].[^\s]*$'
        return bool(re.match(pattern, url))

class ShodanScanner:
    def __init__(self, config: ShodanConfig, output_dir: Path):
        self.config = config
        self.output_dir = output_dir / "shodan"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results: List[Dict[str, Any]] = []

    async def run_shodan_scan(self, ips: Set[str]) -> List[Dict[str, Any]]:
        if not self.config.enabled or not self.config.api_key:
            console.print("[yellow]⚠ Shodan scanning disabled or no API key provided. Skipping.[/yellow]")
            return self.results

        console.print("[cyan]▶ Starting Shodan scanning...[/cyan]")
        try:
            api = shodan.Shodan(self.config.api_key)
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeRemainingColumn(),
                console=console
            ) as progress:
                task_id = progress.add_task("Shodan Scanning", total=len(ips))
                for ip in ips:
                    try:
                        result = api.host(ip)
                        self.results.append({
                            "ip": ip,
                            "ports": result.get("ports", []),
                            "services": result.get("data", []),
                            "os": result.get("os", "Unknown")
                        })
                        async with aiofiles.open(
                            self.output_dir / f"shodan_{ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json", 'w'
                        ) as f:
                            await f.write(json.dumps(result, indent=2))
                        console.print(f"[green]✔ Shodan: Found data for IP {ip}[/green]")
                    except shodan.APIError as e:
                        console.print(f"[red]✖ Shodan error for IP {ip}: {e}[/red]")
                    progress.advance(task_id)
        except Exception as e:
            console.print(f"[red]✖ Shodan initialization error: {e}[/red]")
        return self.results

class TheHarvesterScanner:
    def __init__(self, config: TheHarvesterConfig, domain: str, output_dir: Path):
        self.config = config
        self.domain = domain
        self.output_dir = output_dir / "theharvester"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.emails: Set[str] = set()
        self.social_media: Dict[str, List[str]] = {}

    async def run_harvester_scan(self) -> tuple[Set[str], Dict[str, List[str]]]:
        if not self.config.enabled:
            console.print("[yellow]⚠ TheHarvester scanning disabled. Skipping.[/yellow]")
            return self.emails, self.social_media

        console.print("[cyan]▶ Starting TheHarvester scanning...[/cyan]")
        tool_config = ToolConfig(
            name="theHarvester",
            command="theHarvester -d {domain} -b {sources} -f {output}",
            output_validator=lambda x: bool(x.strip())
        )
        output_file = self.output_dir / f"harvester_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        kwargs = {
            "domain": self.domain,
            "sources": ",".join(self.config.sources),
            "output": str(output_file)
        }

        try:
            result = await self._run_command(tool_config, "TheHarvester Scanning", output_file, **kwargs)
            if result and output_file.exists():
                async with aiofiles.open(output_file, 'r') as f:
                    data = json.loads(await f.read())
                self.emails.update(data.get("emails", []))
                self.social_media = data.get("hosts", {})
                console.print(f"[green]✔ TheHarvester: Found {len(self.emails)} emails and {len(self.social_media)} social media profiles[/green]")
        except Exception as e:
            console.print(f"[red]✖ TheHarvester error: {e}[/red]")

        return self.emails, self.social_media

    async def _run_command(self, tool_config: ToolConfig, task_name: str, output_file: Path, **kwargs) -> Optional[str]:
        command = tool_config.command.format(**kwargs)
        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60)
            result = stdout.decode()
            if process.returncode != 0:
                console.print(f"[red]✖ Error in {task_name}: {stderr.decode()}[/red]")
                return None
            async with aiofiles.open(output_file, 'w') as f:
                await f.write(result)
            return result
        except Exception as e:
            console.print(f"[red]✖ Error in {task_name}: {e}[/red]")
            return None

class GitHubScanner:
    def __init__(self, config: GitHubConfig, domain: str, output_dir: Path, session: ClientSession):
        self.config = config
        self.domain = domain
        self.output_dir = output_dir / "github"
        self.session = session
        self.results: List[str] = []
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def run_github_scan(self) -> List[str]:
        if not self.config.enabled or not self.config.api_key:
            console.print("[yellow]⚠ GitHub scanning disabled or no API key provided. Skipping.[/yellow]")
            return self.results

        console.print("[cyan]▶ Starting GitHub scanning...[/cyan]")
        headers = {"Authorization": f"token {self.config.api_key}"}
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeRemainingColumn(),
            console=console
        ) as progress:
            task_id = progress.add_task("GitHub Scanning", total=len(self.config.search_terms))
            for term in self.config.search_terms:
                formatted_term = term.format(domain=self.domain)
                url = f"https://api.github.com/search/code?q={formatted_term}"
                try:
                    async with self.session.get(url, headers=headers) as response:
                        if response.status != 200:
                            console.print(f"[red]✖ GitHub API error for '{formatted_term}': {response.status}[/red]")
                            continue
                        data = await response.json()
                        items = data.get("items", [])
                        for item in items:
                            self.results.append(item["html_url"])
                        async with aiofiles.open(
                            self.output_dir / f"github_{formatted_term.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt", 'w'
                        ) as f:
                            await f.write('\n'.join(self.results))
                        console.print(f"[green]✔ GitHub: Found {len(items)} results for '{formatted_term}'[/green]")
                except Exception as e:
                    console.print(f"[red]✖ GitHub error for '{formatted_term}': {e}[/red]")
                progress.advance(task_id)
                await asyncio.sleep(self.config.rate_limit)
        return self.results

class UrlFetcher:
    def __init__(self, config: UrlFetcherConfig, output_dir: Path, domain: str, session: ClientSession):
        self.config = config
        self.output_dir = output_dir / "urls"
        self.domain = domain
        self.session = session
        self.tools = {
            "katana": ToolConfig(
                name="katana",
                command="katana -u {input} -d {depth} -ps -pss {sources} {flags} -ef {exclude_extensions} -o {output}",
                version_check="katana --version",
                output_validator=lambda x: bool(x.strip())
            ),
            "gau": ToolConfig(
                name="gau",
                command="echo {domain} | gau --mc {status_codes} | urldedupe",
                version_check="gau --version",
                output_validator=lambda x: bool(x.strip())
            ),
            "httpx-toolkit": ToolConfig(
                name="httpx-toolkit",
                command="httpx-toolkit -mc 200 -content-type",
                version_check="httpx-toolkit --version",
                output_validator=lambda x: bool(x.strip())
            )
        }
        self._initialize_tools()

    def _initialize_tools(self):
        for tool_name, tool_config in self.tools.items():
            try:
                result = subprocess.run(
                    f"which {tool_config.name}",
                    shell=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                tool_config.installed = result.returncode == 0
                if not tool_config.installed:
                    console.print(f"[yellow]⚠ Warning: Tool {tool_name} not installed.[/yellow]")
            except Exception as e:
                console.print(f"[red]✖ Error initializing tool {tool_name}: {e}[/red]")
                tool_config.installed = False

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
    async def _run_command(self, tool_config: ToolConfig, task_name: str, output_file: Optional[Path] = None, **kwargs) -> Optional[str]:
        console.print(f"[cyan]▶ Running {task_name} with {tool_config.name}...[/cyan]")
        command = tool_config.command.format(**kwargs)
        if not self._is_safe_command(command):
            console.print(f"[red]✖ Unsafe command detected: {command}[/red]")
            return None

        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)
            result = stdout.decode()

            if process.returncode != 0:
                console.print(f"[red]✖ Error in {task_name}: {stderr.decode()}[/red]")
                return None

            if tool_config.output_validator and not tool_config.output_validator(result):
                console.print(f"[yellow]⚠ Invalid output from {task_name}[/yellow]")
                return None

            if output_file:
                async with aiofiles.open(output_file, 'w') as f:
                    await f.write(result)
            console.print(f"[green]✔ {task_name} completed successfully.[/green]")
            return result
        except asyncio.TimeoutError:
            console.print(f"[red]✖ Timeout in {task_name}[/red]")
            raise
        except Exception as e:
            console.print(f"[red]✖ Error in {task_name}: {e}[/red]")
            raise

    def _is_safe_command(self, command: str) -> bool:
        dangerous_patterns = [r';', r'&&', r'\|\|', r'`', r'\$']
        return not any(re.search(pattern, command, re.IGNORECASE) for pattern in dangerous_patterns)

    async def fetch_katana_urls(self, input_file: Path, output_file: Path) -> None:
        tool_config = self.tools["katana"]
        if not tool_config.installed:
            console.print("[yellow]⚠ Katana not available. Skipping URL fetching.[/yellow]")
            return

        kwargs = {
            "input": str(input_file),
            "depth": self.config.katana["depth"],
            "sources": ",".join(self.config.katana["sources"]),
            "flags": " ".join(self.config.katana["flags"]),
            "exclude_extensions": ",".join(self.config.katana["exclude_extensions"]),
            "output": str(output_file)
        }
        await self._run_command(tool_config, "Katana URL Fetching", output_file, **kwargs)

    async def fetch_katana_domain_urls(self, output_file: Path) -> None:
        tool_config = ToolConfig(
            name="katana",
            command="echo {domain} | katana -d {depth} -ps -pss {sources} -f qurl | urldedupe",
            output_validator=lambda x: bool(x.strip())
        )
        kwargs = {
            "domain": self.domain,
            "depth": self.config.katana["depth"],
            "sources": ",".join(self.config.katana["sources"])
        }
        await self._run_command(tool_config, "Katana Domain URL Fetching", output_file, **kwargs)

    async def fetch_katana_param_urls(self, output_file: Path) -> None:
        tool_config = ToolConfig(
            name="katana",
            command="katana -u https://{domain} -d {depth} | grep '=' | urldedupe | anew {output}",
            output_validator=lambda x: bool(x.strip())
        )
        kwargs = {
            "domain": self.domain,
            "depth": self.config.katana["depth"],
            "output": str(output_file)
        }
        await self._run_command(tool_config, "Katana Parameter URL Fetching", output_file, **kwargs)

    async def clean_urls(self, input_file: Path, output_file: Path) -> None:
        tool_config = ToolConfig(
            name="sed",
            command="cat {input} | sed 's/=.*/=/' > {output}",
            output_validator=lambda x: bool(x.strip())
        )
        kwargs = {
            "input": str(input_file),
            "output": str(output_file)
        }
        await self._run_command(tool_config, "URL Cleaning", output_file, **kwargs)

    async def fetch_gau_urls(self, output_file: Path) -> None:
        tool_config = self.tools["gau"]
        if not tool_config.installed:
            console.print("[yellow]⚠ Gau not available. Skipping URL fetching.[/yellow]")
            return

        kwargs = {
            "domain": self.domain,
            "status_codes": ",".join(map(str, self.config.gau["status_codes"]))
        }
        await self._run_command(tool_config, "Gau URL Fetching", output_file, **kwargs)

    async def filter_gau_urls(self, input_file: Path, output_file: Path) -> None:
        tool_config = ToolConfig(
            name="grep",
            command="cat {input} | grep -E '{extensions}' | grep '=' | sort > {output}",
            output_validator=lambda x: bool(x.strip())
        )
        kwargs = {
            "input": str(input_file),
            "extensions": "|".join(f"\\.{ext}" for ext in self.config.gau["file_extensions"]),
            "output": str(output_file)
        }
        await self._run_command(tool_config, "Gau URL Filtering", output_file, **kwargs)

    async def analyze_js_files(self, input_file: Path, output_file: Path) -> None:
        tool_config = self.tools["httpx-toolkit"]
        if not tool_config.installed:
            console.print("[yellow]⚠ Httpx-toolkit not available. Skipping JS analysis.[/yellow]")
            return

        temp_file = self.output_dir / "js_urls_temp.txt"
        tool_config_grep = ToolConfig(
            name="grep",
            command="cat {input} | grep -E '\\.js$' > {output}",
            output_validator=lambda x: bool(x.strip())
        )
        await self._run_command(tool_config_grep, "JS File Filtering", temp_file, input=str(input_file), output=str(temp_file))

        js_verified = self.output_dir / "js_verified.txt"
        command = f"cat {temp_file} | {tool_config.command} | grep -E '{ '|'.join(self.config.js_filters['content_types']) }' | cut -d' ' -f1"
        tool_config_verify = ToolConfig(
            name="httpx-toolkit",
            command=command,
            output_validator=lambda x: bool(x.strip())
        )
        await self._run_command(tool_config_verify, "JS Content Type Verification", js_verified)

        sensitive_data = []
        async with aiofiles.open(js_verified, 'r') as f:
            urls = [line.strip() async for line in f]
        
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeRemainingColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Analyzing JS Files", total=len(urls))
            for url in urls:
                try:
                    async with self.session.get(url) as response:
                        if response.status == 200:
                            content = await response.text()
                            for pattern in self.config.js_filters["sensitive_patterns"]:
                                if re.search(pattern, content, re.IGNORECASE):
                                    sensitive_data.append(f"{url}: {pattern}")
                except Exception as e:
                    console.print(f"[yellow]⚠ Error analyzing {url}: {e}[/yellow]")
                progress.advance(task)

        if sensitive_data:
            async with aiofiles.open(output_file, 'w') as f:
                await f.write('\n'.join(sensitive_data))
            console.print(f"[green]✔ Sensitive data found in JS files, saved to {output_file}[/green]")

class AmassScanner:
    def __init__(self, output_dir: Path, domain: str):
        self.output_dir = output_dir / "subdomains"
        self.domain = domain
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.tool_config = ToolConfig(
            name="amass",
            command="amass enum -d {domain} -o {output}",
            version_check="amass --version",
            output_validator=lambda x: bool(x.strip())
        )

    async def run_amass_scan(self) -> Set[str]:
        console.print("[cyan]▶ Starting Amass subdomain enumeration...[/cyan]")
        output_file = self.output_dir / f"amass_subdomains_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        kwargs = {
            "domain": self.domain,
            "output": str(output_file)
        }
        subdomains = set()
        try:
            result = await self._run_command(self.tool_config, "Amass Enumeration", output_file, **kwargs)
            if result and output_file.exists():
                async with aiofiles.open(output_file, 'r') as f:
                    subdomains.update(line.strip() for line in await f.readlines() if line.strip())
                console.print(f"[green]✔ Amass: Found {len(subdomains)} subdomains[/green]")
        except Exception as e:
            console.print(f"[red]✖ Amass error: {e}[/red]")
        return subdomains

    async def _run_command(self, tool_config: ToolConfig, task_name: str, output_file: Path, **kwargs) -> Optional[str]:
        command = tool_config.command.format(**kwargs)
        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60)
            result = stdout.decode()
            if process.returncode != 0:
                console.print(f"[red]✖ Error in {task_name}: {stderr.decode()}[/red]")
                return None
            async with aiofiles.open(output_file, 'w') as f:
                await f.write(result)
            return result
        except Exception as e:
            console.print(f"[red]✖ Error in {task_name}: {e}[/red]")
            return None

class OSINTToolkit:
    CONFIG_SCHEMA = {
        "type": "object",
        "properties": {
            "wordlists": {"type": "object"},
            "api_keys": {"type": "object"},
            "tools": {"type": "object"},
            "cdx_api": {"type": "object"},
            "url_fetcher": {"type": "object"},
            "google_dorks": {"type": "object"},
            "shodan": {"type": "object"},
            "the_harvester": {"type": "object"},
            "github": {"type": "object"},
            "output_formats": {"type": "array", "items": {"type": "string"}}
        }
    }

    DEFAULT_TOOLS = {
        "subfinder": ToolConfig(
            name="subfinder",
            command="subfinder -d {domain} -all -recursive",
            version_check="subfinder --version",
            fallback="dig +short {domain}",
            output_validator=lambda x: bool(x.strip())
        ),
        "httpx": ToolConfig(
            name="httpx",
            command="httpx -ports 80,443,8080,8000,8888 -threads 200",
            version_check="httpx --version",
            output_validator=lambda x: bool(x.strip())
        ),
        "amass": ToolConfig(
            name="amass",
            command="amass enum -d {domain}",
            version_check="amass --version",
            output_validator=lambda x: bool(x.strip())
        )
    }

    def __init__(self, domain: str, config: Config, output_dir: str, active: bool = False, brute: bool = False):
        if not self._is_valid_domain(domain):
            raise ValueError(f"Invalid domain: {domain}")
        
        self.domain = domain
        self.config = config
        self.output_dir = Path(output_dir) / f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.active = active
        self.brute = brute
        self.state = OSINTToolkitState(
            unique_subdomains=set(),
            unique_ips=set(),
            t_history=[],
            t_history_urls=[],
            tool_status={},
            dork_results={},
            emails=set(),
            social_media={},
            github_results=[],
            shodan_results=[]
        )
        self.resolvers = self._load_resolvers()
        self._create_output_dir()
        self._initialize_tools()
        self.session: Optional[ClientSession] = None
        self.url_fetcher: Optional[UrlFetcher] = None
        self.dork_scanner: Optional[GoogleDorkScanner] = None
        self.shodan_scanner: Optional[ShodanScanner] = None
        self.harvester_scanner: Optional[TheHarvesterScanner] = None
        self.github_scanner: Optional[GitHubScanner] = None
        self.amass_scanner: Optional[AmassScanner] = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.config.timeout))
        self.url_fetcher = UrlFetcher(self.config.url_fetcher, self.output_dir, self.domain, self.session)
        self.dork_scanner = GoogleDorkScanner(self.config.google_dorks, self.domain, self.output_dir, self.session)
        self.shodan_scanner = ShodanScanner(self.config.shodan, self.output_dir)
        self.harvester_scanner = TheHarvesterScanner(self.config.the_harvester, self.domain, self.output_dir)
        self.github_scanner = GitHubScanner(self.config.github, self.domain, self.output_dir, self.session)
        self.amass_scanner = AmassScanner(self.output_dir, self.domain)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    def _is_valid_domain(self, domain: str) -> bool:
        pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(pattern, domain))

    def _load_resolvers(self) -> List[str]:
        resolvers_file = self.config.wordlists.get('resolvers', '')
        if resolvers_file and Path(resolvers_file).exists():
            with open(resolvers_file) as f:
                return [line.strip() for line in f if line.strip()]
        console.print("[yellow]⚠ No resolvers file found, using default resolvers.[/yellow]")
        return ['1.1.1.1', '8.8.8.8', '9.9.9.9']

    def _create_output_dir(self) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        subdirs = ['subdomains', 'ports', 'urls', 'emails', 'social_media', 'sensitive_files', 'js_files', 'cors', 'dir_brute', 'ips', 'shodan', 'github', 'dorks', 'theharvester']
        for subdir in subdirs:
            (self.output_dir / subdir).mkdir(exist_ok=True)
        console.print(f"[green]✔ Output directory created at {self.output_dir}[/green]")

    def _initialize_tools(self) -> None:
        for tool_name, tool_config in self.config.tools.items():
            try:
                result = subprocess.run(
                    f"which {tool_config.name}",
                    shell=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                tool_config.installed = result.returncode == 0
                self.state.tool_status[tool_name] = tool_config.installed
                status = "✔ Installed" if tool_config.installed else "✖ Not Installed"
                console.print(f"[cyan]Tool {tool_name}: {status}[/cyan]")
            except Exception as e:
                console.print(f"[red]✖ Error initializing tool {tool_name}: {e}[/red]")
                self.state.tool_status[tool_name] = False

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
    async def _wayback_urls_cdx(self) -> None:
        if not self.config.cdx_api.get("enabled", True):
            console.print("[cyan]▶ Wayback Machine CDX API disabled in config. Skipping.[/cyan]")
            return

        console.print("[cyan]▶ Fetching URLs from Wayback Machine CDX API...[/cyan]")
        output_file = self.output_dir / "urls" / f"wayback_cdx_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        base_url = self.config.cdx_api.get("base_url")
        params = self.config.cdx_api.get("params", {}).copy()
        params["url"] = f"*.{self.domain}/*"

        async with self.session.get(base_url, params=params) as response:
            if response.status != 200:
                console.print(f"[red]✖ Wayback CDX API request failed: {response.status}[/red]")
                raise ValueError(f"API request failed: {response.status}")
            
            urls = await response.text()
            if not urls.strip():
                console.print("[yellow]⚠ No URLs returned from Wayback CDX API.[/yellow]")
                return

            valid_urls = {url.strip() for url in urls.splitlines() if self._is_valid_url(url.strip())}
            async with aiofiles.open(output_file, 'w') as f:
                await f.write('\n'.join(sorted(valid_urls)))
            console.print(f"[green]✔ Wayback CDX URLs saved to {output_file} ({len(valid_urls)} URLs).[/green]")

    def _is_valid_url(self, url: str) -> bool:
        pattern = r'^https?://[^\s/$.?#].[^\s]*$'
        return bool(re.match(pattern, url))

    async def _subfinder(self) -> Set[str]:
        tool_config = self.config.tools.get("subfinder", self.DEFAULT_TOOLS["subfinder"])
        if not tool_config.installed and not tool_config.fallback:
            console.print("[yellow]⚠ Subfinder not available and no fallback provided. Skipping.[/yellow]")
            return set()
        
        output_file = self.output_dir / "subdomains" / f"subdomains_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        result = await self._run_command(tool_config, "Subfinder Enumeration", output_file)
        subdomains = set()
        if result and output_file.exists():
            async with aiofiles.open(output_file, 'r') as f:
                subdomains.update(line.strip() for line in await f.readlines() if line.strip())
        return subdomains

    async def _filter_live_subdomains(self) -> None:
        tool_config = self.config.tools.get("httpx", self.DEFAULT_TOOLS["httpx"])
        if not tool_config.installed:
            console.print("[yellow]⚠ Httpx not available. Skipping live subdomain filtering.[/yellow]")
            return

        command = f"cat {self.output_dir}/subdomains/subdomains_*.txt | {tool_config.command}"
        await self._run_command(
            tool_config,
            "Live Subdomains Filtering",
            self.output_dir / "subdomains" / f"subdomains_alive_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            command=command
        )

    async def passive_enumeration(self) -> None:
        console.print(Panel(f"Starting Passive Enumeration for {self.domain}", title="OSINTToolkit", style="cyan"))
        tasks = [
            (self._subfinder, "Subfinder", True),
            (self.amass_scanner.run_amass_scan, "Amass", True),
            (self._filter_live_subdomains, "Live Subdomains", False),
            (self._wayback_urls_cdx, "Wayback CDX", False),
            (self.dork_scanner.run_dork_scan, "Google Dork Scanning", True),
            (self.harvester_scanner.run_harvester_scan, "TheHarvester", True),
            (self.github_scanner.run_github_scan, "GitHub Scanning", True)
        ]

        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeRemainingColumn(),
            console=console
        ) as progress:
            task_id = progress.add_task("Passive Enumeration", total=len(tasks) + 4)
            for task, name, returns_value in tasks:
                try:
                    if name == "Google Dork Scanning":
                        self.state.dork_results = await task()
                    elif name == "TheHarvester":
                        self.state.emails, self.state.social_media = await task()
                    elif name == "GitHub Scanning":
                        self.state.github_results = await task()
                    elif name == "Subfinder":
                        self.state.unique_subdomains.update(await task())
                    elif name == "Amass":
                        self.state.unique_subdomains.update(await task())
                    else:
                        await task()
                    console.print(f"[green]✔ Completed {name}[/green]")
                    progress.advance(task_id)
                except Exception as e:
                    console.print(f"[red]✖ Failed task {name}: {e}[/red]")
                    self.state.tool_status[name.lower()] = False

            # URL Fetching
            subdomains_file = self.output_dir / "subdomains" / f"subdomains_alive_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            async with aiofiles.open(subdomains_file, 'w') as f:
                await f.write('\n'.join(self.state.unique_subdomains))
            await self.url_fetcher.fetch_katana_urls(
                subdomains_file,
                self.output_dir / "urls" / f"allurls_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            )
            progress.advance(task_id)

            temp_output = self.output_dir / "urls" / f"output_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            await self.url_fetcher.fetch_katana_domain_urls(temp_output)
            await self.url_fetcher.fetch_katana_param_urls(temp_output)
            await self.url_fetcher.clean_urls(temp_output, self.output_dir / "urls" / f"final_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
            progress.advance(task_id)

            gau_output = self.output_dir / "urls" / f"urls_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            await self.url_fetcher.fetch_gau_urls(gau_output)
            await self.url_fetcher.filter_gau_urls(gau_output, self.output_dir / "urls" / f"gau_output_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
            await self.url_fetcher.clean_urls(
                self.output_dir / "urls" / f"gau_output_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                self.output_dir / "urls" / f"gau_final_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            )
            await self.url_fetcher.analyze_js_files(
                self.output_dir / "urls" / f"allurls_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                self.output_dir / "js_files" / f"sensitive_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            )
            progress.advance(task_id)

            # Shodan scanning
            await self._process_ips()
            self.state.shodan_results = await self.shodan_scanner.run_shodan_scan(self.state.unique_ips)
            progress.advance(task_id)

        await self._process_subdomains()

    async def _run_command(self, tool_config: ToolConfig, task_name: str, output_file: Optional[Path] = None, **kwargs) -> Optional[str]:
        command = tool_config.command.format(domain=self.domain, **kwargs)
        if not self._is_safe_command(command):
            console.print(f"[red]✖ Unsafe command detected: {command}[/red]")
            return None

        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=self.config.timeout)
            result = stdout.decode()
            if process.returncode != 0:
                console.print(f"[red]✖ Error in {task_name}: {stderr.decode()}[/red]")
                return None
            if output_file:
                async with aiofiles.open(output_file, 'w') as f:
                    await f.write(result)
            console.print(f"[green]✔ {task_name} completed successfully.[/green]")
            return result
        except asyncio.TimeoutError:
            console.print(f"[red]✖ Timeout in {task_name}[/red]")
            raise
        except Exception as e:
            console.print(f"[red]✖ Error in {task_name}: {e}[/red]")
            raise

    def _is_safe_command(self, command: str) -> bool:
        dangerous_patterns = [r';', r'&&', r'\|\|', r'`', r'\$']
        return not any(re.search(pattern, command, re.IGNORECASE) for pattern in dangerous_patterns)

    async def _process_subdomains(self) -> None:
        cleaned = {s.lower().strip() for s in self.state.unique_subdomains if s.strip()}
        async with aiofiles.open(self.output_dir / 'subdomains' / 'final_subdomains.txt', 'w') as f:
            await f.write('\n'.join(sorted(cleaned)))
        
        self.state.unique_subdomains = cleaned
        console.print(f"[green]✔ Total unique subdomains: {len(self.state.unique_subdomains)}[/green]")

    async def _process_ips(self) -> None:
        all_ips = []
        for file in (self.output_dir / 'ips').glob('*.txt'):
            async with aiofiles.open(file, 'r') as f:
                content = await f.read()
                all_ips.extend(content.splitlines())
        
        cleaned = {ip.strip() for ip in all_ips if ip.strip() and re.match(r'([0-9]{1,3}\.){3}[0-9]{1,3}', ip)}
        async with aiofiles.open(self.output_dir / 'ips' / 'all_ips.txt', 'w') as f:
            await f.write('\n'.join(sorted(cleaned)))
        
        self.state.unique_ips = cleaned
        console.print(f"[green]✔ Total unique IPs: {len(self.state.unique_ips)}[/green]")

    async def generate_report(self) -> None:
        report = {
            "domain": self.domain,
            "timestamp": datetime.now().isoformat(),
            "tool_status": self.state.tool_status,
            "subdomains": {
                "count": len(self.state.unique_subdomains),
                "list": sorted(list(self.state.unique_subdomains))
            },
            "ips": {
                "count": len(self.state.unique_ips),
                "list": sorted(list(self.state.unique_ips))
            },
            "urls": {
                "count": 0,
                "list": []
            },
            "sensitive_js_findings": [],
            "dork_results": self.state.dork_results,
            "emails": sorted(list(self.state.emails)),
            "social_media": self.state.social_media,
            "github_results": self.state.github_results,
            "shodan_results": self.state.shodan_results,
            "issues": []
        }

        # Aggregate URLs
        all_urls = set()
        for file in (self.output_dir / 'urls').glob('*.txt'):
            async with aiofiles.open(file, 'r') as f:
                content = await f.read()
                all_urls.update(line.strip() for line in content.splitlines() if self._is_valid_url(line.strip()))
        report["urls"]["count"] = len(all_urls)
        report["urls"]["list"] = sorted(list(all_urls))

        # Aggregate sensitive JS findings
        for file in (self.output_dir / 'js_files').glob('sensitive_*.txt'):
            async with aiofiles.open(file, 'r') as f:
                content = await f.read()
                report["sensitive_js_findings"].extend(line.strip() for line in content.splitlines() if line.strip())

        # Collect issues
        for tool_name, status in self.state.tool_status.items():
            if not status:
                report["issues"].append(f"Tool {tool_name} failed or is not installed.")
        if self.config.google_dorks.enabled and not (self.config.google_dorks.api_key and self.config.google_dorks.cse_id):
            report["issues"].append("Google dork scanning used scraping due to missing API key or CSE ID.")
        if self.config.shodan.enabled and not self.config.shodan.api_key:
            report["issues"].append("Shodan scanning skipped due to missing API key.")
        if self.config.github.enabled and not self.config.github.api_key:
            report["issues"].append("GitHub scanning skipped due to missing API key.")

        # JSON output
        if "json" in self.config.output_formats:
            async with aiofiles.open(self.output_dir / "results.json", 'w') as f:
                await f.write(json.dumps(report, indent=2))
            console.print(f"[green]✔ JSON report saved to {self.output_dir / 'results.json'}[/green]")

        # Markdown output
        if "markdown" in self.config.output_formats:
            markdown_content = f"""
# OSINTToolkit Report for {self.domain}

Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Summary
- **Domain**: {self.domain}
- **Subdomains Found**: {report["subdomains"]["count"]}
- **IPs Found**: {report["ips"]["count"]}
- **URLs Found**: {report["urls"]["count"]}
- **Sensitive JS Findings**: {len(report["sensitive_js_findings"])}
- **Google Dork Findings**: {sum(len(results) for results in report["dork_results"].values())}
- **Emails Found**: {len(report["emails"])}
- **Social Media Profiles**: {sum(len(profiles) for profiles in report["social_media"].values())}
- **GitHub Results**: {len(report["github_results"])}
- **Shodan Results**: {len(report["shodan_results"])}

## Tool Status
| Tool | Status |
|------|--------|
"""
            for tool, status in report["tool_status"].items():
                markdown_content += f"| {tool} | {'✅ Installed' if status else '❌ Not Installed'} |\n"

            markdown_content += "\n## Issues\n"
            if report["issues"]:
                for issue in report["issues"]:
                    markdown_content += f"- {issue}\n"
            else:
                markdown_content += "- None\n"

            markdown_content += "\n## Subdomains\n<details>\n<summary>View {report['subdomains']['count']} Subdomains</summary>\n\n"
            for subdomain in report["subdomains"]["list"][:50]:
                markdown_content += f"- {subdomain}\n"
            if len(report["subdomains"]["list"]) > 50:
                markdown_content += f"- ... and {len(report['subdomains']['list']) - 50} more\n"
            markdown_content += "</details>\n"

            markdown_content += "\n## IPs\n<details>\n<summary>View {report['ips']['count']} IPs</summary>\n\n"
            for ip in report["ips"]["list"][:50]:
                markdown_content += f"- {ip}\n"
            if len(report["ips"]["list"]) > 50:
                markdown_content += f"- ... and {len(report['ips']['list']) - 50} more\n"
            markdown_content += "</details>\n"

            markdown_content += "\n## URLs\n<details>\n<summary>View {report['urls']['count']} URLs</summary>\n\n"
            for url in report["urls"]["list"][:50]:
                markdown_content += f"- {url}\n"
            if len(report["urls"]["list"]) > 50:
                markdown_content += f"- ... and {len(report['urls']['list']) - 50} more\n"
            markdown_content += "</details>\n"

            markdown_content += "\n## Sensitive JavaScript Findings\n"
            if report["sensitive_js_findings"]:
                for finding in report["sensitive_js_findings"][:10]:
                    markdown_content += f"- {finding}\n"
                if len(report["sensitive_js_findings"]) > 10:
                    markdown_content += f"- ... and {len(report['sensitive_js_findings']) - 10} more\n"
            else:
                markdown_content += "- None\n"

            markdown_content += "\n## Google Dork Findings\n"
            for category, results in report["dork_results"].items():
                markdown_content += f"\n### {category.replace('_', ' ').title()}\n<details>\n<summary>View {len(results)} Results</summary>\n\n"
                if results:
                    markdown_content += "| URL |\n|----|\n"
                    for url in results[:10]:
                        markdown_content += f"| {url} |\n"
                    if len(results) > 10:
                        markdown_content += f"| ... and {len(results) - 10} more |\n"
                else:
                    markdown_content += "- None\n"
                markdown_content += "</details>\n"

            markdown_content += "\n## Emails\n<details>\n<summary>View {len(report['emails'])} Emails</summary>\n\n"
            for email in report["emails"][:50]:
                markdown_content += f"- {email}\n"
            if len(report["emails"]) > 50:
                markdown_content += f"- ... and {len(report['emails']) - 50} more\n"
            markdown_content += "</details>\n"

            markdown_content += "\n## Social Media Profiles\n"
            for platform, profiles in report["social_media"].items():
                markdown_content += f"\n### {platform.title()}\n<details>\n<summary>View {len(profiles)} Profiles</summary>\n\n"
                for profile in profiles[:10]:
                    markdown_content += f"- {profile}\n"
                if len(profiles) > 10:
                    markdown_content += f"- ... and {len(profiles) - 10} more\n"
                markdown_content += "</details>\n"

            markdown_content += "\n## GitHub Results\n<details>\n<summary>View {len(report['github_results'])} Results</summary>\n\n"
            for result in report["github_results"][:50]:
                markdown_content += f"- {result}\n"
            if len(report["github_results"]) > 50:
                markdown_content += f"- ... and {len(report['github_results']) - 50} more\n"
            markdown_content += "</details>\n"

            markdown_content += "\n## Shodan Results\n<details>\n<summary>View {len(report['shodan_results'])} IPs</summary>\n\n"
            for result in report["shodan_results"][:50]:
                markdown_content += f"- **IP**: {result['ip']} | **Ports**: {', '.join(map(str, result['ports']))} | **OS**: {result['os']}\n"
            if len(report["shodan_results"]) > 50:
                markdown_content += f"- ... and {len(report['shodan_results']) - 50} more\n"
            markdown_content += "</details>\n"

            async with aiofiles.open(self.output_dir / "report.md", 'w') as f:
                await f.write(markdown_content)
            console.print(f"[green]✔ Markdown report saved to {self.output_dir / 'report.md'}[/green]")

        # CSV output
        if "csv" in self.config.output_formats:
            csv_data = [
                ["Domain", self.domain],
                ["Subdomains", report["subdomains"]["count"]],
                ["IPs", report["ips"]["count"]],
                ["URLs", report["urls"]["count"]],
                ["Sensitive JS Findings", len(report["sensitive_js_findings"])],
                ["Google Dork Findings", sum(len(results) for results in report["dork_results"].values())],
                ["Emails", len(report["emails"])],
                ["Social Media Profiles", sum(len(profiles) for profiles in report["social_media"].values())],
                ["GitHub Results", len(report["github_results"])],
                ["Shodan Results", len(report["shodan_results"])]
            ]
            csv_content = tabulate(csv_data, headers=["Metric", "Value"], tablefmt="plain")
            async with aiofiles.open(self.output_dir / "summary.csv", 'w') as f:
                await f.write(csv_content)
            console.print(f"[green]✔ CSV report saved to {self.output_dir / 'summary.csv'}[/green]")

        # Terminal summary
        table = Table(title="OSINTToolkit Summary", style="cyan")
        table.add_column("Metric", style="bold")
        table.add_column("Value", style="bold")
        table.add_row("Domain", self.domain)
        table.add_row("Subdomains", str(report["subdomains"]["count"]))
        table.add_row("IPs", str(report["ips"]["count"]))
        table.add_row("URLs", str(report["urls"]["count"]))
        table.add_row("Sensitive JS Findings", str(len(report["sensitive_js_findings"])))
        table.add_row("Google Dork Findings", str(sum(len(results) for results in report["dork_results"].values())))
        table.add_row("Emails", str(len(report["emails"])))
        table.add_row("Social Media Profiles", str(sum(len(profiles) for profiles in report["social_media"].values())))
        table.add_row("GitHub Results", str(len(report["github_results"])))
        table.add_row("Shodan Results", str(len(report["shodan_results"])))
        console.print(table)

def load_config(config_file: Optional[str]) -> Config:
    if not config_file or not Path(config_file).exists():
        console.print("[yellow]⚠ No config file provided, using defaults.[/yellow]")
        return Config(
            wordlists={},
            api_keys={},
            tools=OSINTToolkit.DEFAULT_TOOLS,
            cdx_api=None,
            url_fetcher=None,
            google_dorks=None,
            shodan=None,
            the_harvester=None,
            github=None
        )
    
    try:
        with open(config_file, 'r') as f:
            config_data = json.load(f)
        validate(instance=config_data, schema=OSINTToolkit.CONFIG_SCHEMA)
        
        tools = {
            name: ToolConfig(
                name=name,
                command=cfg["command"],
                version_check=cfg.get("version_check"),
                fallback=cfg.get("fallback"),
                required=cfg.get("required", True)
            ) for name, cfg in config_data.get("tools", {}).items()
        }
        tools.update(OSINTToolkit.DEFAULT_TOOLS)
        
        google_dorks = GoogleDorkConfig(
            enabled=config_data.get("google_dorks", {}).get("enabled", True),
            api_key=config_data.get("google_dorks", {}).get("api_key", ""),
            cse_id=config_data.get("google_dorks", {}).get("cse_id", ""),
            queries=config_data.get("google_dorks", {}).get("queries", Config.__post_init__.__defaults__[0].google_dorks.queries),
            proxy_pool=config_data.get("google_dorks", {}).get("proxy_pool", []),
            max_results=config_data.get("google_dorks", {}).get("max_results", 100)
        )
        
        shodan = ShodanConfig(
            enabled=config_data.get("shodan", {}).get("enabled", True),
            api_key=config_data.get("shodan", {}).get("api_key", "")
        )
        
        the_harvester = TheHarvesterConfig(
            enabled=config_data.get("the_harvester", {}).get("enabled", True),
            sources=config_data.get("the_harvester", {}).get("sources", ["bing", "google", "linkedin", "twitter"])
        )
        
        github = GitHubConfig(
            enabled=config_data.get("github", {}).get("enabled", True),
            api_key=config_data.get("github", {}).get("api_key", ""),
            search_terms=config_data.get("github", {}).get("search_terms", ["{domain} api_key", "{domain} secret", "{domain} password"])
        )
        
        return Config(
            wordlists=config_data.get('wordlists', {}),
            api_keys=config_data.get('api_keys', {}),
            tools=tools,
            cdx_api=config_data.get('cdx_api'),
            url_fetcher=config_data.get('url_fetcher'),
            google_dorks=google_dorks,
            shodan=shodan,
            the_harvester=the_harvester,
            github=github,
            output_formats=config_data.get('output_formats')
        )
    except (json.JSONDecodeError, ValidationError) as e:
        console.print(f"[red]✖ Error loading config file: {e}[/red]")
        return Config(
            wordlists={},
            api_keys={},
            tools=OSINTToolkit.DEFAULT_TOOLS,
            cdx_api=None,
            url_fetcher=None,
            google_dorks=None,
            shodan=None,
            the_harvester=None,
            github=None
        )

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Advanced OSINT Toolkit for Reconnaissance",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument("-o", "--output-dir", default="./output", help="Output directory")
    parser.add_argument("--active", action="store_true", help="Enable active enumeration")
    parser.add_argument("--brute", action="store_true", help="Enable brute force enumeration")
    parser.add_argument("--config", help="Path to configuration file (JSON)")
    parser.add_argument("--vt-key", help="VirusTotal API key")
    parser.add_argument("--av-key", help="AlienVault API key")
    parser.add_argument("--wpscan-key", help="WPScan API key")
    parser.add_argument("--google-api-key", help="Google Custom Search API key")
    parser.add_argument("--google-cse-id", help="Google Custom Search Engine ID")
    parser.add_argument("--shodan-key", help="Shodan API key")
    parser.add_argument("--github-key", help="GitHub API key")
    return parser.parse_args()

async def main():
    args = parse_args()
    config = load_config(args.config)
    
    config.api_keys.update({
        'virustotal': args.vt_key or config.api_keys.get('virustotal', ''),
        'alienvault': args.av_key or config.api_keys.get('alienvault', ''),
        'wpscan': args.wpscan_key or config.api_keys.get('wpscan', '')
    })
    config.google_dorks.api_key = args.google_api_key or config.google_dorks.api_key
    config.google_dorks.cse_id = args.google_cse_id or config.google_dorks.cse_id
    config.shodan.api_key = args.shodan_key or config.shodan.api_key
    config.github.api_key = args.github_key or config.github.api_key

    async with OSINTToolkit(
        domain=args.domain,
        config=config,
        output_dir=args.output_dir,
        active=args.active,
        brute=args.brute
    ) as toolkit:
        await toolkit.passive_enumeration()
        if args.active:
            await toolkit.active_enumeration()
        await toolkit.generate_report()

if __name__ == "__main__":
    asyncio.run(main())