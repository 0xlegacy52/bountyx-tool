#!/bin/bash

# Port scanning module for BountyX

# Run port scanning
run_port_scan() {
    echo -e "${GREEN}Running Port Scanning against ${BLUE}$TARGET${NC}"
    
    local start_time=$(date +%s)
    
    setup_tor
    
    # Create port scan output directory
    mkdir -p "$OUTPUT_DIR/ports"
    
    local target_list="$OUTPUT_DIR/ports/targets.txt"
    local target_type=$(get_target_type "$TARGET")
    
    # Determine targets for port scanning
    if [[ "$target_type" == "domain" ]]; then
        # If a domain was specified, use the discovered subdomains or live hosts
        if [[ -f "$OUTPUT_DIR/livehosts/alive_hosts.txt" && -s "$OUTPUT_DIR/livehosts/alive_hosts.txt" ]]; then
            cp "$OUTPUT_DIR/livehosts/alive_hosts.txt" "$target_list"
            echo -e "${YELLOW}Using live hosts from previous scan...${NC}"
        elif [[ -f "$OUTPUT_DIR/subdomains/unique_subdomains.txt" && -s "$OUTPUT_DIR/subdomains/unique_subdomains.txt" ]]; then
            cp "$OUTPUT_DIR/subdomains/unique_subdomains.txt" "$target_list"
            echo -e "${YELLOW}Using subdomains from previous scan...${NC}"
        else
            echo "$TARGET" > "$target_list"
            echo -e "${YELLOW}No previous subdomain or live host results found, using main target...${NC}"
        fi
    else
        # For IP addresses or CIDR, use the target directly
        echo "$TARGET" > "$target_list"
    fi
    
    # Double-check if the target list is empty or only contains empty lines
    if [[ ! -s "$target_list" || $(grep -v '^$' "$target_list" | wc -l) -eq 0 ]]; then
        echo "$TARGET" > "$target_list"
        echo -e "${YELLOW}Target list was empty, using main target...${NC}"
    fi
    
    local masscan_output="$OUTPUT_DIR/ports/masscan_output.txt"
    local nmap_output="$OUTPUT_DIR/ports/nmap_output"
    local combined_output="$OUTPUT_DIR/ports/all_ports.txt"
    
    # Run masscan for quick discovery if available
    if command_exists "masscan" && [[ "$target_type" != "domain" ]]; then
        echo -e "${YELLOW}Running masscan for quick port discovery...${NC}"
        if $USE_TOR; then
            echo -e "${RED}Warning: masscan does not support Tor proxy. Running without Tor.${NC}"
        fi
        sudo masscan -p1-65535 --rate=1000 -iL "$target_list" -oG "$masscan_output" 2>/dev/null || true
        
        # Extract ports from masscan output for nmap scan
        if [[ -f "$masscan_output" ]]; then
            local masscan_ports=$(grep "Ports:" "$masscan_output" | cut -d" " -f4 | cut -d"/" -f1 | sort -n | uniq | tr '\n' ',' | sed 's/,$//')
            if [[ -n "$masscan_ports" ]]; then
                echo -e "${GREEN}Masscan found ports: ${BLUE}$masscan_ports${NC}"
                local nmap_port_args="-p$masscan_ports"
            else
                echo -e "${YELLOW}Masscan did not find any open ports, falling back to top ports...${NC}"
                local nmap_port_args="-p 80,443,21,22,25,53,110,143,3306,8080,8443"
            fi
        else
            local nmap_port_args="-p 80,443,21,22,25,53,110,143,3306,8080,8443"
        fi
    else
        if ! command_exists "masscan"; then
            echo -e "${YELLOW}masscan not found, using nmap only...${NC}"
        else
            echo -e "${YELLOW}Target is a domain, skipping masscan and using nmap only...${NC}"
        fi
        local nmap_port_args="-p 80,443,21,22,25,53,110,143,3306,8080,8443"
    fi
    
    # Run nmap for detailed port scanning
    echo -e "${YELLOW}Running nmap for detailed port scanning...${NC}"
    if command_exists "nmap"; then
        local proxy_args=""
        if $USE_TOR; then
            proxy_args="--proxies socks4://127.0.0.1:9050"
        fi
        
        nmap -sV -sC $nmap_port_args -iL "$target_list" $proxy_args -oA "$nmap_output" --open
        
        # Check if XML output exists
        if [[ -f "${nmap_output}.xml" ]]; then
            # Convert XML to more readable format if jq is available
            if command_exists "jq"; then
                echo -e "${YELLOW}Converting nmap output to JSON...${NC}"
                if command_exists "xsltproc"; then
                    xsltproc "${nmap_output}.xml" -o "${nmap_output}.html"
                    
                    # Try to extract key information to JSON
                    local json_output="$OUTPUT_DIR/ports/ports.json"
                    grep -oP 'Host: \K[^\s]+' "${nmap_output}.nmap" | sort -u > "$OUTPUT_DIR/ports/scanned_hosts.txt"
                    grep -A10 "PORT" "${nmap_output}.nmap" | grep -v "^--" > "$combined_output"
                    
                    # Create a simple JSON structure
                    echo "{\"scan_results\": [" > "$json_output"
                    local hosts=$(cat "$OUTPUT_DIR/ports/scanned_hosts.txt")
                    local first_host=true
                    
                    for host in $hosts; do
                        if $first_host; then
                            first_host=false
                        else
                            echo "," >> "$json_output"
                        fi
                        
                        echo "{\"host\": \"$host\", \"ports\": [" >> "$json_output"
                        
                        local ports=$(grep -A10 "Nmap scan report for $host" "${nmap_output}.nmap" | grep -oP '^\d+/\w+\s+\w+\s+\K.*' || echo "")
                        local first_port=true
                        
                        echo "$ports" | while read -r port_info; do
                            if [[ -n "$port_info" ]]; then
                                if $first_port; then
                                    first_port=false
                                else
                                    echo "," >> "$json_output"
                                fi
                                
                                local port_num=$(echo "$port_info" | grep -oP '^\d+')
                                local service=$(echo "$port_info" | awk '{print $1}')
                                local version=$(echo "$port_info" | awk '{$1=""; print $0}' | xargs)
                                
                                echo "{\"port\": $port_num, \"service\": \"$service\", \"version\": \"$version\"}" >> "$json_output"
                            fi
                        done
                        
                        echo "]}" >> "$json_output"
                    done
                    
                    echo "]}" >> "$json_output"
                fi
            else
                echo -e "${YELLOW}jq not found, skipping JSON conversion...${NC}"
                cp "${nmap_output}.nmap" "$combined_output"
            fi
        else
            echo -e "${RED}No nmap output found, something went wrong...${NC}"
        fi
    else
        echo -e "${RED}nmap not found, port scanning is not possible.${NC}"
    fi
    
    local end_time=$(date +%s)
    print_elapsed_time $start_time $end_time
    
    echo -e "${GREEN}Port scanning completed! Results saved to ${BLUE}$OUTPUT_DIR/ports/${NC}"
    
    # If interactive mode, prompt to continue
    if [[ -z "$SCAN_TYPE" || "$SCAN_TYPE" == "portscan" ]]; then
        echo -e "Press Enter to return to the main menu..."
        read
        show_menu
    fi
}
