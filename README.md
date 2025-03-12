
# SUBDO

## OSINT Toolkit

**Advanced OSINT Toolkit for Reconnaissance**  
**Version: 2.1**  
**Description:** A powerful Python-based toolkit designed for subdomain enumeration, IP discovery, vulnerability scanning, and reconnaissance tasks. It integrates various OSINT techniques and tools to provide comprehensive insights into a target domain.

---

## Features

- **Subdomain Enumeration**: Discover subdomains using tools like `subfinder`, VirusTotal, and AlienVault OTX.
- **IP Extraction**: Extract IP addresses from VirusTotal, AlienVault OTX, URLScan.io, and Shodan.
- **Passive URL Fetching**: Retrieve historical URLs from Wayback Machine and passive sources using `katana`.
- **Active Scanning**: Perform directory bruteforce, XSS testing, LFI testing, and network scanning.
- **API Integration**: Supports VirusTotal, AlienVault OTX, and WPScan APIs for enriched data collection.
- **Output Organization**: Results are saved in a structured directory with subfolders for subdomains, IPs, URLs, etc.
- **Customizable**: Accepts command-line arguments and a configuration file for flexibility.

---

## Requirements

### Dependencies
- **Python**: 3.6 or higher
- **Python Libraries**:
  - `requests`
  - `beautifulsoup4`
- **External Tools**:
  - `subfinder`
  - `httpx-toolkit`
  - `katana`
  - `arjun`
  - `wpscan`
  - `ffuf`
  - `nuclei`
  - `subzy`
  - `curl`
  - `gau`
  - `dirsearch`
  - `naabu`
  - `nmap`
  - `masscan`
  - `jq` (for JSON parsing)

### API Keys (Optional)
- VirusTotal API Key
- AlienVault OTX API Key
- WPScan API Key

---

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/osint-toolkit.git
   cd osint-toolkit
   ```

2. **Install Python Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
   Create a `requirements.txt` file with:
   ```
   requests
   beautifulsoup4
   ```

3. **Install External Tools**:
   Use your package manager (e.g., `apt`, `brew`, or direct downloads) to install the required tools. Example for Ubuntu:
   ```bash
   sudo apt update
   sudo apt install curl jq nmap
   go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
   go install github.com/projectdiscovery/httpx/cmd/httpx@latest
   # Install other tools similarly
   ```

4. **Set Up API Keys** (Optional):
   Create a `config.json` file or pass keys via command-line arguments (see Usage).

---

## Usage

Run the toolkit using Python with command-line arguments:

```bash
python osint_toolkit.py -d <domain> [options]
```

### Command-Line Arguments
| Argument          | Description                                      | Required | Default       |
|-------------------|--------------------------------------------------|----------|---------------|
| `-d, --domain`    | Target domain (e.g., `example.com`)             | Yes      | N/A           |
| `-o, --output-dir`| Output directory                                | No       | `./output`    |
| `--active`        | Enable active enumeration                       | No       | False         |
| `--brute`         | Enable brute force enumeration                  | No       | False         |
| `--config`        | Path to configuration file (JSON)               | No       | None          |
| `--vt-key`        | VirusTotal API key                              | No       | None          |
| `--av-key`        | AlienVault OTX API key                          | No       | None          |
| `--wpscan-key`    | WPScan API key                                  | No       | None          |

### Configuration File
Create a `config.json` file to specify wordlists and API keys:
```json
{
    "wordlists": {
        "resolvers": "/path/to/resolvers.txt",
        "dns": "/path/to/dns_wordlist.txt",
        "lfi": "/path/to/lfi_payloads.txt",
        "dir": "/path/to/dir_wordlist.txt",
        "parameters": "/usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt"
    },
    "api_keys": {
        "virustotal": "your_vt_key",
        "alienvault": "your_av_key",
        "wpscan": "your_wpscan_key"
    }
}
```

### Examples
1. **Basic Passive Enumeration**:
   ```bash
   python osint_toolkit.py -d example.com
   ```

2. **Full Recon with Active Scanning**:
   ```bash
   python osint_toolkit.py -d example.com -o ./results --active --brute --config config.json
   ```

3. **With API Keys**:
   ```bash
   python osint_toolkit.py -d example.com --vt-key YOUR_VT_KEY --wpscan-key YOUR_WPSCAN_KEY
   ```

---

## Supported Techniques

### Subdomain Enumeration
- `subfinder`: Recursive subdomain discovery.
- VirusTotal API: Subdomains and IPs from domain reports.
- AlienVault OTX: Subdomains from passive DNS.

### IP Extraction
- VirusTotal: IPs from domain reports.
- AlienVault OTX: IPs from URL lists.
- URLScan.io: IPs from search results.
- Shodan: IPs from SSL certificate searches.

### Passive URL Fetching
- `katana`: Passive URLs from Wayback Machine, Common Crawl, and AlienVault.
- Wayback Machine: Historical URLs via CDX API.

### Active Scanning
- Directory Bruteforce: `dirsearch` and `ffuf`.
- XSS Testing: Blind and single XSS checks.
- LFI Testing: Using `gau` and `ffuf`.
- Network Scanning: `naabu`, `nmap`, `masscan`.
- Shodan: SSL certificate searches with HTTP verification.
- Nmap: SSL certificate inspection on IPs.

### Vulnerability Checks
- Hidden Parameters: `arjun` with custom wordlists.
- CORS Misconfiguration: `curl` checks.
- WordPress Scanning: Aggressive `wpscan`.
- Subdomain Takeover: `subzy`.
- JS File Hunting: `katana` and `nuclei`.

---

## Output Structure

Results are saved in the specified output directory (default: `./output`) with the following structure:
```
output/
├── subdomains/        # Subdomain enumeration results
├── ips/              # Extracted IP addresses
├── urls/             # Passive and sorted URLs
├── ports/            # Network scanning results
├── sensitive_files/  # Sensitive file discoveries
├── js_files/         # JS file hunting results
├── cors/             # CORS check results
├── xss/              # XSS testing results
├── lfi/              # LFI testing results
├── dir_brute/        # Directory bruteforce results
├── shodan/           # Shodan search results
├── emails/           # (Future use)
└── social_media/     # (Future use)
```

---

## Notes
- **API Keys**: Required for VirusTotal, AlienVault OTX, and WPScan features. Omit them for basic functionality.
- **Shodan Favicon Search**: Manual step; use `http.favicon.hash:1265477436` in Shodan UI.
- **Performance**: Active enumeration may take time depending on target size and network conditions.
- **Error Handling**: Missing tools or invalid inputs will display error messages.

---

## Contributing
Feel free to submit issues or pull requests to improve the toolkit. Contributions are welcome!

---

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.

---

## Acknowledgments
- Built with inspiration from open-source reconnaissance tools.
- Thanks to the developers of `subfinder`, `katana`, `ffuf`, and other integrated tools.

---

```

### ملاحظات حول ملف README
1. **التنظيم**: تم تقسيم الملف إلى أقسام واضحة لسهولة القراءة.
2. **التفاصيل**: يشمل تعليمات التثبيت، الاستخدام، والتقنيات المدعومة مع أمثلة عملية.
3. **المرونة**: يوضح كيفية استخدام الوسيطات وملف التهيئة معًا.
4. **التوثيق**: يشرح هيكل الإخراج والملاحظات الهامة للمستخدمين.
