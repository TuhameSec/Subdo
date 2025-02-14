# SUBDO

## Overview
Subdo is a powerful tool for discovering subdomains, performing passive and active enumeration, port scanning, and URL enumeration. It integrates multiple tools to gather comprehensive data about the target domain and organizes the results in a structured format for further analysis.

## Features
- **Passive Subdomain Enumeration** using tools like `subfinder` and Censys.io.
- **Active Subdomain Enumeration** with `massdns` for high-performance DNS resolution.
- **Port Scanning** with `masscan` to detect open ports on discovered subdomains.
- **URL Enumeration** with `waybackurls` and `gau` to gather potential endpoints and historical data.

## Requirements
- **subfinder**: A fast subdomain discovery tool.
- **assetfinder**: A tool for finding subdomains of a target domain.
- **knockpy**: A Python tool for DNS subdomain enumeration.
- **findomain**: A fast subdomain enumeration tool.
- **massdns**: A high-performance DNS resolver.
- **httpx**: A tool for probing HTTP servers.
- **waybackurls**: A tool to get URLs from the Wayback Machine.
- **gau**: A tool for gathering URLs from various sources like Wayback Machine, Common Crawl, and more.

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Shad0Sec/Subdo.git
   cd Subdo
   ```

2. **Install required dependencies**:
   Ensure that the following tools are installed and available in your system’s PATH:
   - `subfinder`
   - `assetfinder`
   - `knockpy`
   - `findomain`
   - `massdns`
   - `httpx`
   - `waybackurls`
   - `gau`
   
   You can install them using the following commands:
   ```bash
   sudo apt install subfinder assetfinder knockpy findomain massdns httpx waybackurls gau
   ```

## Usage

### Basic Usage
```bash
python3 subdo.py -d <target-domain>
```

Where:
- `-d <target-domain>`: The domain you want to enumerate subdomains for.

### Optional Arguments
- `-c <config-file>`: Path to a custom configuration file (optional).
- `-o <output-dir>`: Custom output directory for saving the results (optional).

### Example
```bash
python3 subdo.py -d example.com -o /path/to/output
```

This will start the enumeration process for `example.com` and save the results in the specified directory.

### Phases of Enumeration
1. **Passive Enumeration**: Using tools like `subfinder` and Censys.io to find subdomains without actively scanning the target.
2. **Active Enumeration**: Using `massdns` to resolve subdomains to IP addresses.
3. **Port Scanning**: Using `masscan` to scan discovered IPs for open ports.
4. **URL Enumeration**: Using `waybackurls` and `gau` to discover URLs and endpoints associated with the target domain.

## Configuration
The tool uses a default configuration located in the `CONFIG` dictionary. If you need to customize settings, you can:
- Modify the default configuration in the script.
- Use the `-c` option to specify a custom JSON configuration file.

### Example of Configuration:
```json
{
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
```

## API Keys
You can provide API keys for Censys and GitHub when running the tool:
- Censys API key (optional)
- GitHub Token (optional)

These keys can be entered interactively when prompted during execution.

## Results
All results will be saved in the `results` directory (or a custom directory if specified). The output is organized into the following subdirectories:
- `subdomains`: Contains the list of discovered subdomains.
- `ports`: Contains the IPs and port scan results.
- `urls`: Contains the discovered URLs.

## Troubleshooting
If you encounter issues with missing dependencies, the tool will notify you of any missing tools and exit. Make sure that all the required tools are installed and available in your system's PATH.

## License
This tool is licensed under the MIT License.

## Contributing
Feel free to fork the repository and submit pull requests to improve the tool. Contributions are always welcome!

## Author
This tool was created by [Shad0Sec].
