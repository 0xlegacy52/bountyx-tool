# BountyX - Advanced Bug Bounty Hunting Tool

<p align="center">
  <img src="https://raw.githubusercontent.com/feathericons/feather/master/icons/shield.svg" width="100" height="100" alt="BountyX Logo">
</p>

BountyX is a comprehensive, modular Bash-based tool designed for bug bounty hunters and security professionals. It automates the reconnaissance, scanning, and vulnerability detection processes, allowing researchers to focus on analyzing results rather than managing multiple tools.

## Features

- **Subdomain Enumeration**: Discover subdomains using `amass`, `subfinder`, and `assetfinder`
- **Port Scanning**: Identify open ports and services with `nmap` and `masscan`
- **Directory & File Enumeration**: Find hidden directories and files using `ffuf`, `dirsearch`, or `gobuster`
- **Live Host Detection**: Determine which discovered hosts are active with `httpx` or `httprobe`
- **Vulnerability Scanning**: Detect common vulnerabilities with `nuclei` and built-in checks
- **Web Screenshots**: Capture visual evidence with `gowitness` or `aquatone`
- **AI-Powered Analysis**: Process and prioritize findings with the integrated AI helper
- **Interactive Menu**: Easily control all functions through a user-friendly CLI
- **Structured Output**: Save results in JSON, TXT, or HTML formats
- **Tor Support**: Route traffic through Tor for anonymity (optional)

## Installation

```bash
git clone https://github.com/0xlegacy52/bountyx-tool.git
cd bountyx-tool
chmod +x install.sh
./install.sh
