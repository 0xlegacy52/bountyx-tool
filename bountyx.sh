#!/bin/bash

# BountyX - A comprehensive Bug Bounty hunting tool
# Author: BountyX Team
# License: MIT
# Version: 1.0.0

# Setting bash strict mode
set -euo pipefail
IFS=$'\n\t'

# Define colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Config variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/results"
THREADS=10
TARGET=""
SCAN_TYPE="all"
OUTPUT_FORMAT="json"
USE_TOR=false

# Load modules
source "$SCRIPT_DIR/modules/utils.sh"
source "$SCRIPT_DIR/modules/subdomain_enum.sh"
source "$SCRIPT_DIR/modules/port_scan.sh"
source "$SCRIPT_DIR/modules/dir_enum.sh"
source "$SCRIPT_DIR/modules/live_host.sh"
source "$SCRIPT_DIR/modules/vulnerability_scan.sh"
source "$SCRIPT_DIR/modules/screenshot.sh"

# Print banner
print_banner() {
    echo -e "${BLUE}"
    echo "██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗██╗  ██╗"
    echo "██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝╚██╗██╔╝"
    echo "██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝  ╚███╔╝ "
    echo "██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝   ██╔██╗ "
    echo "██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║   ██╔╝ ██╗"
    echo "╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝"
    echo -e "${NC}"
    echo -e "${GREEN}A comprehensive Bug Bounty hunting tool${NC}"
    echo -e "${YELLOW}Version: 1.0.0${NC}"
    echo -e "${YELLOW}Author: BountyX Team${NC}"
    echo
}

# Print help message
print_help() {
    echo -e "${GREEN}Usage:${NC} ./bountyx.sh [options]"
    echo
    echo -e "${BLUE}Options:${NC}"
    echo -e "  -h, --help\t\tShow this help message"
    echo -e "  -t, --target\t\tSpecify target domain (required)"
    echo -e "  -m, --module\t\tSpecify module to run (subdomain, portscan, direnum, livehost, vulnscan, screenshot, all)"
    echo -e "  -o, --output\t\tSpecify output format (json, txt, html) [default: json]"
    echo -e "  -T, --threads\t\tSpecify number of threads [default: 10]"
    echo -e "  --tor\t\t\tUse Tor proxy for anonymity"
    echo
    echo -e "${BLUE}Examples:${NC}"
    echo -e "  ./bountyx.sh -t example.com"
    echo -e "  ./bountyx.sh -t example.com -m subdomain -o json"
    echo -e "  ./bountyx.sh -t example.com --tor -T 20"
    echo
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                print_help
                exit 0
                ;;
            -t|--target)
                TARGET="$2"
                shift 2
                ;;
            -m|--module)
                SCAN_TYPE="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_FORMAT="$2"
                shift 2
                ;;
            -T|--threads)
                THREADS="$2"
                shift 2
                ;;
            --tor)
                USE_TOR=true
                shift
                ;;
            *)
                echo -e "${RED}Error: Unknown option $1${NC}"
                print_help
                exit 1
                ;;
        esac
    done

    # Check if target is provided
    if [[ -z "$TARGET" ]]; then
        echo -e "${RED}Error: Target domain is required${NC}"
        print_help
        exit 1
    fi
}

# Interactive menu
show_menu() {
    clear
    print_banner
    echo -e "${BLUE}Target:${NC} $TARGET"
    echo
    echo -e "${GREEN}Select an option:${NC}"
    echo -e "${YELLOW}1.${NC} Run all modules"
    echo -e "${YELLOW}2.${NC} Subdomain Enumeration"
    echo -e "${YELLOW}3.${NC} Port Scanning"
    echo -e "${YELLOW}4.${NC} Directory Enumeration"
    echo -e "${YELLOW}5.${NC} Live Host Detection"
    echo -e "${YELLOW}6.${NC} Vulnerability Scanning"
    echo -e "${YELLOW}7.${NC} Website Screenshots"
    echo -e "${YELLOW}8.${NC} AI Analysis of Results"
    echo -e "${YELLOW}9.${NC} Configure Settings"
    echo -e "${YELLOW}0.${NC} Exit"
    echo
    read -p "Enter your choice: " choice

    case $choice in
        1) run_all_modules ;;
        2) run_subdomain_enum ;;
        3) run_port_scan ;;
        4) run_dir_enum ;;
        5) run_live_host ;;
        6) run_vuln_scan ;;
        7) run_screenshot ;;
        8) run_ai_analysis ;;
        9) configure_settings ;;
        0) exit 0 ;;
        *) 
            echo -e "${RED}Invalid option. Press Enter to continue...${NC}"
            read
            show_menu
            ;;
    esac
}

# Configure settings
configure_settings() {
    clear
    echo -e "${BLUE}Current Settings:${NC}"
    echo -e "${GREEN}Target:${NC} $TARGET"
    echo -e "${GREEN}Threads:${NC} $THREADS"
    echo -e "${GREEN}Output Format:${NC} $OUTPUT_FORMAT"
    echo -e "${GREEN}Use Tor:${NC} $USE_TOR"
    echo
    echo -e "${YELLOW}1.${NC} Change Target"
    echo -e "${YELLOW}2.${NC} Change Threads"
    echo -e "${YELLOW}3.${NC} Change Output Format"
    echo -e "${YELLOW}4.${NC} Toggle Tor"
    echo -e "${YELLOW}5.${NC} Back to Main Menu"
    echo
    read -p "Enter your choice: " choice

    case $choice in
        1)
            read -p "Enter new target domain: " TARGET
            configure_settings
            ;;
        2)
            read -p "Enter number of threads: " THREADS
            configure_settings
            ;;
        3)
            echo "Available formats: json, txt, html"
            read -p "Enter output format: " OUTPUT_FORMAT
            configure_settings
            ;;
        4)
            if $USE_TOR; then
                USE_TOR=false
            else
                USE_TOR=true
            fi
            configure_settings
            ;;
        5) 
            show_menu
            ;;
        *)
            echo -e "${RED}Invalid option. Press Enter to continue...${NC}"
            read
            configure_settings
            ;;
    esac
}

# Run all modules
run_all_modules() {
    clear
    print_banner
    echo -e "${GREEN}Running all modules against ${BLUE}$TARGET${NC}"
    echo

    # Create results directory
    create_output_dir
    
    # Run modules in sequence
    run_subdomain_enum
    run_live_host
    run_port_scan
    run_dir_enum
    run_vuln_scan
    run_screenshot
    run_ai_analysis
    
    echo -e "${GREEN}All scans completed! Results saved in ${BLUE}$OUTPUT_DIR${NC}"
    echo -e "Press Enter to return to the main menu..."
    read
    show_menu
}

# Run AI analysis
run_ai_analysis() {
    echo -e "${GREEN}Running AI Analysis on scan results...${NC}"
    python3 "$SCRIPT_DIR/ai_helper.py" --target "$TARGET" --input-dir "$OUTPUT_DIR" --output-format "$OUTPUT_FORMAT"
    echo -e "${GREEN}AI Analysis completed!${NC}"
}

# Create output directory structure
create_output_dir() {
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    OUTPUT_DIR="$SCRIPT_DIR/results/${TARGET}_${TIMESTAMP}"
    mkdir -p "$OUTPUT_DIR"
    mkdir -p "$OUTPUT_DIR/subdomains"
    mkdir -p "$OUTPUT_DIR/ports"
    mkdir -p "$OUTPUT_DIR/directories"
    mkdir -p "$OUTPUT_DIR/livehosts"
    mkdir -p "$OUTPUT_DIR/vulnerabilities"
    mkdir -p "$OUTPUT_DIR/screenshots"
    mkdir -p "$OUTPUT_DIR/analysis"
    
    echo -e "${GREEN}Created output directory: ${BLUE}$OUTPUT_DIR${NC}"
}

# Main function
main() {
    # Check for required dependencies
    check_dependencies
    
    # Parse command line arguments if provided
    if [[ $# -gt 0 ]]; then
        parse_args "$@"
        
        # Create output directory
        create_output_dir
        
        # Run specified module or all modules
        case $SCAN_TYPE in
            subdomain) run_subdomain_enum ;;
            portscan) run_port_scan ;;
            direnum) run_dir_enum ;;
            livehost) run_live_host ;;
            vulnscan) run_vuln_scan ;;
            screenshot) run_screenshot ;;
            all) run_all_modules ;;
            *)
                echo -e "${RED}Error: Unknown module $SCAN_TYPE${NC}"
                print_help
                exit 1
                ;;
        esac
    else
        # Show interactive menu if no arguments provided
        show_menu
    fi
}

# Run main function
main "$@"
