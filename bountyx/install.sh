#!/bin/bash

# BountyX Installer Script
# This script installs all dependencies required for BountyX

# Define colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print banner
echo -e "${BLUE}"
echo "██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗██╗  ██╗"
echo "██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝╚██╗██╔╝"
echo "██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝  ╚███╔╝ "
echo "██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝   ██╔██╗ "
echo "██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║   ██╔╝ ██╗"
echo "╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝"
echo -e "${NC}"
echo -e "${GREEN}BountyX Installer${NC}"
echo -e "${YELLOW}This script will install all dependencies required for BountyX${NC}"
echo

# Check if script is run as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${YELLOW}This script will install system packages and might need sudo privileges.${NC}"
   echo -e "${YELLOW}Continue? (y/n)${NC}"
   read -r continue_install
   if [[ "$continue_install" != "y" ]]; then
       echo -e "${RED}Installation aborted.${NC}"
       exit 1
   fi
fi

# Make main script executable
echo -e "${BLUE}Making BountyX script executable...${NC}"
chmod +x bountyx.sh
echo -e "${GREEN}Done!${NC}"

# Create required directories
echo -e "${BLUE}Creating required directories...${NC}"
mkdir -p results
echo -e "${GREEN}Done!${NC}"

# Detect OS
echo -e "${BLUE}Detecting operating system...${NC}"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    OS_VERSION=$VERSION_ID
    echo -e "${GREEN}Detected: $OS $OS_VERSION${NC}"
else
    echo -e "${RED}Cannot detect OS, assuming Debian-based...${NC}"
    OS="debian"
fi

# Install essential dependencies
echo -e "${BLUE}Installing essential dependencies...${NC}"
case $OS in
    "debian"|"ubuntu"|"kali"|"parrot")
        sudo apt update
        sudo apt install -y curl wget jq python3 python3-pip nmap
        ;;
    "fedora"|"centos"|"rhel")
        sudo dnf update -y
        sudo dnf install -y curl wget jq python3 python3-pip nmap
        ;;
    "arch"|"manjaro")
        sudo pacman -Syu --noconfirm
        sudo pacman -S --noconfirm curl wget jq python python-pip nmap
        ;;
    *)
        echo -e "${RED}Unsupported OS. Please install dependencies manually:${NC}"
        echo "curl wget jq python3 python3-pip nmap"
        ;;
esac
echo -e "${GREEN}Essential dependencies installed!${NC}"

# Install Go (required for many tools)
echo -e "${BLUE}Checking for Go installation...${NC}"
if ! command -v go &> /dev/null; then
    echo -e "${YELLOW}Go not found. Installing Go...${NC}"
    
    GO_VERSION="1.20"
    GO_TAR="go${GO_VERSION}.linux-amd64.tar.gz"
    
    wget https://go.dev/dl/${GO_TAR}
    sudo tar -C /usr/local -xzf ${GO_TAR}
    rm ${GO_TAR}
    
    # Add Go to PATH
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    
    echo -e "${GREEN}Go installed!${NC}"
else
    echo -e "${GREEN}Go already installed!${NC}"
fi

# Install Python dependencies
echo -e "${BLUE}Installing Python dependencies...${NC}"
cat > requirements.txt << EOF
requests
argparse
tqdm
python-dateutil
EOF

pip3 install -r requirements.txt

# Check if AI modules are available
echo -e "${BLUE}Checking for AI modules...${NC}"
if pip3 install openai -q; then
    echo -e "${GREEN}OpenAI module installed!${NC}"
else
    echo -e "${YELLOW}OpenAI module installation failed. AI features will be limited.${NC}"
fi

if pip3 install transformers -q; then
    echo -e "${GREEN}Transformers module installed!${NC}"
else
    echo -e "${YELLOW}Transformers module installation failed. AI features will be limited.${NC}"
fi

echo -e "${GREEN}Python dependencies installed!${NC}"

# Install optional tools
echo -e "${BLUE}Would you like to install recommended bug bounty tools? (y/n)${NC}"
read -r install_tools

if [[ "$install_tools" == "y" ]]; then
    echo -e "${BLUE}Installing tools...${NC}"
    
    # Install Go-based tools
    echo -e "${YELLOW}Installing Go-based tools...${NC}"
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
    go install -v github.com/tomnomnom/assetfinder@latest
    go install -v github.com/ffuf/ffuf@latest
    go install -v github.com/sensepost/gowitness@latest
    go install -v github.com/tomnomnom/httprobe@latest
    
    # Install OS-specific packages
    echo -e "${YELLOW}Installing distribution packages...${NC}"
    case $OS in
        "debian"|"ubuntu"|"kali"|"parrot")
            sudo apt install -y amass dirsearch gobuster masscan
            ;;
        "fedora"|"centos"|"rhel")
            sudo dnf install -y amass masscan
            # Some tools might need to be installed manually
            ;;
        "arch"|"manjaro")
            sudo pacman -S --noconfirm amass gobuster masscan
            ;;
        *)
            echo -e "${RED}Unsupported OS. Please install tools manually.${NC}"
            ;;
    esac
    
    echo -e "${GREEN}Tools installed!${NC}"
else
    echo -e "${YELLOW}Skipping tool installation. You can install them later as needed.${NC}"
fi

# Setup Tor for anonymity (optional)
echo -e "${BLUE}Would you like to install Tor for anonymous scanning? (y/n)${NC}"
read -r install_tor

if [[ "$install_tor" == "y" ]]; then
    echo -e "${BLUE}Installing Tor...${NC}"
    case $OS in
        "debian"|"ubuntu"|"kali"|"parrot")
            sudo apt install -y tor
            ;;
        "fedora"|"centos"|"rhel")
            sudo dnf install -y tor
            ;;
        "arch"|"manjaro")
            sudo pacman -S --noconfirm tor
            ;;
        *)
            echo -e "${RED}Unsupported OS. Please install Tor manually.${NC}"
            ;;
    esac
    
    # Start Tor service
    sudo systemctl enable tor
    sudo systemctl start tor
    
    echo -e "${GREEN}Tor installed and started!${NC}"
else
    echo -e "${YELLOW}Skipping Tor installation.${NC}"
fi

# Final setup
echo -e "${BLUE}Creating results directory...${NC}"
mkdir -p results
echo -e "${GREEN}Done!${NC}"

# Installation complete
echo -e "${GREEN}BountyX installation complete!${NC}"
echo -e "${BLUE}To run BountyX, use: ${YELLOW}./bountyx.sh${NC}"
echo -e "${BLUE}For help, use: ${YELLOW}./bountyx.sh --help${NC}"
echo
echo -e "${YELLOW}Note: Some tools may require additional configuration.${NC}"
echo -e "${YELLOW}Please check the README.md for more information.${NC}"
