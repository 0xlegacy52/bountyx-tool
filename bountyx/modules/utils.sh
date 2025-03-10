#!/bin/bash

# Utility functions for BountyX

# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check for required dependencies
check_dependencies() {
    echo -e "${BLUE}Checking dependencies...${NC}"
    
    MISSING_DEPS=()
    
    # Essential tools
    ESSENTIAL_TOOLS=("curl" "wget" "jq" "python3" "nmap")
    for tool in "${ESSENTIAL_TOOLS[@]}"; do
        if ! command_exists "$tool"; then
            MISSING_DEPS+=("$tool")
        fi
    done
    
    # Optional but recommended tools
    OPTIONAL_TOOLS=("amass" "subfinder" "assetfinder" "masscan" "ffuf" "dirsearch" "gobuster" "httpx" "nuclei" "gowitness" "aquatone")
    MISSING_OPTIONAL=()
    for tool in "${OPTIONAL_TOOLS[@]}"; do
        if ! command_exists "$tool"; then
            MISSING_OPTIONAL+=("$tool")
        fi
    done
    
    # If essential tools are missing, exit
    if [[ ${#MISSING_DEPS[@]} -gt 0 ]]; then
        echo -e "${RED}Error: The following essential dependencies are missing:${NC}"
        for dep in "${MISSING_DEPS[@]}"; do
            echo -e "  - $dep"
        done
        echo -e "${YELLOW}Please install these dependencies and try again.${NC}"
        exit 1
    fi
    
    # If optional tools are missing, warn but continue
    if [[ ${#MISSING_OPTIONAL[@]} -gt 0 ]]; then
        echo -e "${YELLOW}Warning: The following recommended tools are missing:${NC}"
        for tool in "${MISSING_OPTIONAL[@]}"; do
            echo -e "  - $tool"
        done
        echo -e "${YELLOW}Some functionality may be limited. Continuing automatically...${NC}"
        # Auto continue with yes for testing
        response="y"
        # Uncomment below for interactive mode
        # echo -e "${YELLOW}Some functionality may be limited. Continue? (y/n)${NC}"
        # read -r response
        if [[ "$response" != "y" ]]; then
            echo -e "${RED}Exiting.${NC}"
            exit 1
        fi
    fi
    
    echo -e "${GREEN}All essential dependencies are installed!${NC}"
}

# Setup Tor proxy if requested
setup_tor() {
    if $USE_TOR; then
        if ! command_exists "tor"; then
            echo -e "${YELLOW}Tor is not installed. Skipping Tor setup...${NC}"
            export TOR_PROXY=""
            return 0
        fi
        
        # Check if Tor process is running
        if ! pgrep -x "tor" > /dev/null; then
            echo -e "${YELLOW}Tor service is not running. Starting Tor...${NC}"
            # Start tor in background
            tor &
            # Wait for tor to start up
            sleep 5
        fi
        
        # Check if Tor is properly set up
        if ! curl --socks5 127.0.0.1:9050 --connect-timeout 10 https://check.torproject.org/ > /dev/null 2>&1; then
            echo -e "${YELLOW}Could not connect to Tor network. Continuing without Tor...${NC}"
            export TOR_PROXY=""
            return 0
        fi
        
        echo -e "${GREEN}Tor proxy configured successfully!${NC}"
        export TOR_PROXY="--proxy socks5://127.0.0.1:9050"
    else
        export TOR_PROXY=""
    fi
}

# Save results to file in specified format
save_results() {
    local module="$1"
    local data="$2"
    local filename="$3"
    
    case $OUTPUT_FORMAT in
        json)
            echo "$data" | jq > "$filename.json"
            ;;
        txt)
            echo "$data" > "$filename.txt"
            ;;
        html)
            echo "<html><head><title>BountyX Results - $module</title><style>body{font-family:Arial,sans-serif;margin:20px}h1{color:#2c3e50}pre{background-color:#f8f9fa;padding:15px;border-radius:5px;overflow:auto}</style></head><body><h1>BountyX Results - $module</h1><pre>$data</pre></body></html>" > "$filename.html"
            ;;
        *)
            echo -e "${RED}Error: Unknown output format $OUTPUT_FORMAT${NC}"
            echo "$data" > "$filename.txt"
            ;;
    esac
}

# Combine results from multiple tools
combine_results() {
    local output_file="$1"
    shift
    local input_files=("$@")
    
    case $OUTPUT_FORMAT in
        json)
            jq -s 'add' "${input_files[@]}" > "$output_file.json"
            ;;
        txt)
            cat "${input_files[@]}" > "$output_file.txt"
            ;;
        html)
            {
                echo "<html><head><title>BountyX Combined Results</title><style>body{font-family:Arial,sans-serif;margin:20px}h1,h2{color:#2c3e50}pre{background-color:#f8f9fa;padding:15px;border-radius:5px;overflow:auto}</style></head><body><h1>BountyX Combined Results</h1>"
                for file in "${input_files[@]}"; do
                    module_name=$(basename "$file" | cut -d. -f1)
                    echo "<h2>$module_name</h2>"
                    echo "<pre>"
                    cat "$file"
                    echo "</pre>"
                done
                echo "</body></html>"
            } > "$output_file.html"
            ;;
    esac
}

# Format elapsed time
format_time() {
    local seconds=$1
    local minutes=$((seconds / 60))
    local remaining_seconds=$((seconds % 60))
    
    if [[ $minutes -gt 0 ]]; then
        echo "${minutes}m ${remaining_seconds}s"
    else
        echo "${seconds}s"
    fi
}

# Print elapsed time
print_elapsed_time() {
    local start_time=$1
    local end_time=$2
    local elapsed=$((end_time - start_time))
    
    echo -e "${BLUE}Elapsed time: $(format_time $elapsed)${NC}"
}

# Check if IP is valid
is_valid_ip() {
    local ip=$1
    local stat=1
    
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -r -a ip_array <<< "$ip"
        [[ ${ip_array[0]} -le 255 && ${ip_array[1]} -le 255 && ${ip_array[2]} -le 255 && ${ip_array[3]} -le 255 ]]
        stat=$?
    fi
    
    return $stat
}

# Check if domain is valid
is_valid_domain() {
    local domain=$1
    [[ $domain =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]
    return $?
}

# Get target type (domain, IP, CIDR)
get_target_type() {
    local target=$1
    
    if is_valid_ip "$target"; then
        echo "ip"
    elif [[ $target =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        echo "cidr"
    elif is_valid_domain "$target"; then
        echo "domain"
    else
        echo "unknown"
    fi
}
