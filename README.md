OSINTToolkit
OSINTToolkit is an advanced, open-source intelligence (OSINT) reconnaissance tool designed to gather comprehensive and accurate data about a target domain. Built for security researchers, penetration testers, and OSINT enthusiasts, it combines multiple data sources, intelligent analysis, and robust error handling to deliver unparalleled results. With features like AI-driven dynamic dork generation, dark web scanning, and interactive dashboards, OSINTToolkit aims to set a new standard in OSINT automation.
Features

Comprehensive Data Collection:

Subdomain enumeration using Subfinder, Amass, and DNS resolvers.
URL discovery via Katana, Gau, and Wayback Machine CDX API.
Google dork scanning with dynamic query generation powered by AI.
Email and social media harvesting with theHarvester.
GitHub code leak detection for sensitive data.
IP and port scanning with Shodan, Censys, and BinaryEdge.
Cloud storage leak detection (AWS S3, Azure, GCP).
Dark web scanning for hidden services on Tor.


Intelligent Analysis:

AI-based result classification using DistilBERT for prioritizing sensitive findings.
Dynamic Google dork generation tailored to the target domain.
Sentiment analysis for social media profiles.


Organized Output:

Structured JSON, Markdown, CSV, and PDF reports.
Interactive web dashboard built with FastAPI and Plotly for real-time data visualization.
SQLite database for storing and querying results.
Customizable report templates with full Arabic language support.


Performance and Reliability:

Asynchronous processing with asyncio for high-speed data collection.
Distributed scanning support for large-scale targets (e.g., Kubernetes).
Smart rate limiting and proxy rotation to bypass API restrictions.
Self-healing mechanisms to handle tool failures and network issues.


Security and Stealth:

Stealth mode with Tor and VPN integration for minimal digital footprint.
Automated vulnerability scanning with Nuclei for discovered URLs.
Threat intelligence integration with VirusTotal and AlienVault.



Installation
Prerequisites

Operating System: Linux (Ubuntu/Debian recommended) or macOS
Python: Version 3.8 or higher
Dependencies:
Install required tools: subfinder, amass, katana, gau, httpx, theHarvester, nuclei
Install Tor for dark web scanning (optional)


API Keys (optional but recommended):
Google Custom Search API (for advanced dork scanning)
Shodan (for IP/port scanning)
GitHub (for code leak detection)
VirusTotal, AlienVault (for threat intelligence)
Censys, BinaryEdge (for additional IP scanning)



Setup

Clone the Repository:
git clone https://github.com/TuhameSec/Subdo.git
cd Subdo


Install Python Dependencies:
pip install -r requirements.txt

Sample requirements.txt:
aiohttp==3.8.5
aiofiles==23.2.1
jsonschema==4.19.0
tenacity==8.2.3
rich==13.5.2
tabulate==0.9.0
google-api-python-client==2.97.0
shodan==1.30.0
transformers==4.33.0
fastapi==0.103.1
uvicorn==0.23.2
jinja2==3.1.2
cloud_enum==0.7
stem==1.8.2
nuclei==2.9.15


Install External Tools:
# Install Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Install Amass
go install -v github.com/OWASP/Amass/v3/...@master

# Install Katana
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Install Gau
go install github.com/lc/gau/v2/cmd/gau@latest

# Install httpx
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# Install theHarvester
pip install theHarvester

# Install Nuclei
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest


Configure API Keys:Create a config.json file in the project root:
{
  "wordlists": {
    "resolvers": "/path/to/resolvers.txt",
    "dns": "/path/to/dns_wordlist.txt"
  },
  "api_keys": {
    "google_api_key": "YOUR_GOOGLE_API_KEY",
    "google_cse_id": "YOUR_GOOGLE_CSE_ID",
    "shodan": "YOUR_SHODAN_API_KEY",
    "github": "YOUR_GITHUB_API_KEY",
    "virustotal": "YOUR_VIRUSTOTAL_API_KEY",
    "alienvault": "YOUR_ALIENVAULT_API_KEY"
  },
  "tools": {
    "subfinder": {
      "command": "subfinder -d {domain} -all -recursive",
      "version_check": "subfinder --version",
      "required": true
    },
    "amass": {
      "command": "amass enum -d {domain}",
      "version_check": "amass --version",
      "required": true
    }
  },
  "output_formats": ["json", "markdown", "csv", "pdf"],
  "stealth_mode": false
}


(Optional) Set Up Tor for Dark Web Scanning:
sudo apt-get install tor
sudo systemctl start tor



Usage
Run the tool with the following command:
python subdo.py -d example.com -o ./output --config config.json

Command-Line Arguments



Argument
Description
Required
Default



-d, --domain
Target domain (e.g., example.com)
Yes
-


-o, --output-dir
Output directory for results
No
./output


--config
Path to configuration file (JSON)
No
-


--active
Enable active enumeration
No
False


--brute
Enable brute force enumeration
No
False


--vt-key
VirusTotal API key
No
-


--av-key
AlienVault API key
No
-


--google-api-key
Google Custom Search API key
No
-


--google-cse-id
Google Custom Search Engine ID
No
-


--shodan-key
Shodan API key
No
-


--github-key
GitHub API key
No
-


Example
python subdo.py -d example.com -o ./results --config config.json --active --google-api-key YOUR_KEY --google-cse-id YOUR_CSE_ID

This command:

Targets example.com.
Saves results to ./results.
Uses the provided configuration file.
Enables active enumeration.
Uses Google Custom Search API for dork scanning.

Interactive Dashboard
Start the FastAPI dashboard to visualize results:
uvicorn subdo:app --host 0.0.0.0 --port 8000

Access the dashboard at http://localhost:8000. Features include:

Real-time result filtering by category (subdomains, URLs, dorks, etc.).
Interactive charts for data trends (e.g., subdomain count over time).
Downloadable reports in multiple formats.

Output Structure
Results are saved in the specified output directory (./output by default) with the following structure:
output/run_YYYYMMDD_HHMMSS/
├── subdomains/
│   ├── subdomains_YYYYMMDD_HHMMSS.txt
│   ├── subdomains_alive_YYYYMMDD_HHMMSS.txt
│   └── final_subdomains.txt
├── urls/
│   ├── allurls_YYYYMMDD_HHMMSS.txt
│   ├── gau_output_YYYYMMDD_HHMMSS.txt
│   └── final_YYYYMMDD_HHMMSS.txt
├── dorks/
│   ├── basic_recon_YYYYMMDD_HHMMSS.txt
│   ├── sensitive_files_YYYYMMDD_HHMMSS.txt
│   └── ...
├── js_files/
│   └── sensitive_YYYYMMDD_HHMMSS.txt
├── emails/
├── social_media/
├── github/
├── shodan/
├── cloud_leaks/
├── dark_web/
├── vulnerabilities/
├── results.json
├── report.md
├── summary.csv
├── report.pdf
└── results.db (SQLite database)

Report Formats

JSON: Structured data with all findings.
Markdown: Detailed report with collapsible sections for readability.
CSV: Summary of key metrics (e.g., subdomain count, URLs found).
PDF: Professional report with customizable templates.

Contributing
Contributions are welcome! To contribute:

Fork the repository.
Create a new branch (git checkout -b feature/your-feature).
Make your changes and commit (git commit -m "Add your feature").
Push to your branch (git push origin feature/your-feature).
Open a pull request.

Please ensure your code follows the project's coding standards and includes tests.
License
This project is licensed under the MIT License. See the LICENSE file for details.
Disclaimer
OSINTToolkit is intended for authorized security testing and research purposes only. Unauthorized use against systems or networks without explicit permission is illegal. The developers are not responsible for misuse of the tool.
Contact
For questions, bug reports, or feature requests, open an issue on GitHub or contact the maintainers at support@xai.org.

🌟 OSINTToolkit: Turning reconnaissance into an art form. Let's make the competition rethink their career choices! 🍅
