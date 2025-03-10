#!/bin/bash

# Subdomain enumeration module for BountyX

# Run subdomain enumeration
run_subdomain_enum() {
    echo -e "${GREEN}Running Subdomain Enumeration against ${BLUE}$TARGET${NC}"
    
    local start_time=$(date +%s)
    local target_type=$(get_target_type "$TARGET")
    
    # Skip for IP addresses or CIDR
    if [[ "$target_type" != "domain" ]]; then
        echo -e "${YELLOW}Subdomain enumeration is only available for domains, skipping...${NC}"
        return
    fi
    
    setup_tor
    
    # Create subdomain output directory if it doesn't exist
    mkdir -p "$OUTPUT_DIR/subdomains"
    
    local amass_output="$OUTPUT_DIR/subdomains/amass_output.txt"
    local subfinder_output="$OUTPUT_DIR/subdomains/subfinder_output.txt"
    local assetfinder_output="$OUTPUT_DIR/subdomains/assetfinder_output.txt"
    local combined_output="$OUTPUT_DIR/subdomains/all_subdomains.txt"
    local unique_output="$OUTPUT_DIR/subdomains/unique_subdomains.txt"
    
    # Run amass if available
    if command_exists "amass"; then
        echo -e "${YELLOW}Running amass...${NC}"
        amass enum -d "$TARGET" -o "$amass_output" $TOR_PROXY
    else
        echo -e "${YELLOW}amass not found, skipping...${NC}"
    fi
    
    # Run subfinder if available
    if command_exists "subfinder"; then
        echo -e "${YELLOW}Running subfinder...${NC}"
        subfinder -d "$TARGET" -o "$subfinder_output" $TOR_PROXY
    else
        echo -e "${YELLOW}subfinder not found, skipping...${NC}"
    fi
    
    # Run assetfinder if available
    if command_exists "assetfinder"; then
        echo -e "${YELLOW}Running assetfinder...${NC}"
        assetfinder --subs-only "$TARGET" > "$assetfinder_output"
    else
        echo -e "${YELLOW}assetfinder not found, skipping...${NC}"
    fi
    
    # Basic DNS method using dig if no specialized tools are available
    if ! command_exists "amass" && ! command_exists "subfinder" && ! command_exists "assetfinder"; then
        echo -e "${YELLOW}No specialized subdomain tools found, using basic DNS method...${NC}"
        local dns_output="$OUTPUT_DIR/subdomains/dns_output.txt"
        
        # Create a list of common subdomain prefixes
        local common_subdomains=(
            "www" "mail" "smtp" "pop" "pop3" "imap" "ftp" "ns1" "ns2" "ns3" "dns" "dns1" "dns2"
            "mx" "mx1" "mx2" "webmail" "email" "test" "dev" "staging" "prod" "production" "vpn"
            "admin" "api" "blog" "shop" "store" "cdn" "cloud" "portal" "secure" "status" "beta"
            "m" "mobile" "app" "support" "help" "login" "remote" "server" "database" "db" "gateway"
            "gitlab" "git" "jenkins" "ci" "jira" "wiki" "confluence" "docs" "documentation"
        )
        
        echo -e "${YELLOW}Checking common subdomains via DNS...${NC}"
        for sub in "${common_subdomains[@]}"; do
            local subdomain="$sub.$TARGET"
            # Try to resolve the subdomain
            if dig +short "$subdomain" > /dev/null 2>&1; then
                echo "$subdomain" >> "$dns_output"
                echo -e "${GREEN}Found subdomain: ${BLUE}$subdomain${NC}"
            fi
        done
        
        # Try to get subdomains with DNS zone transfer if possible
        echo -e "${YELLOW}Attempting DNS zone transfer...${NC}"
        local nameservers=$(dig +short NS "$TARGET")
        if [[ -n "$nameservers" ]]; then
            for ns in $nameservers; do
                dig @"$ns" "$TARGET" AXFR >> "$dns_output" 2>/dev/null
            done
        fi
        
        # Try reverse DNS lookup on common IP ranges if the domain resolves
        local domain_ip=$(dig +short "$TARGET" | head -n1)
        if [[ -n "$domain_ip" ]]; then
            echo -e "${YELLOW}Attempting reverse DNS lookups...${NC}"
            # Get the first two octets for a Class B sweep
            local ip_prefix=$(echo "$domain_ip" | cut -d'.' -f1-2)
            for i in {1..5}; do  # Just check a few IPs to not overload
                local check_ip="$ip_prefix.0.$i"
                local reverse=$(dig +short -x "$check_ip" 2>/dev/null)
                if [[ "$reverse" == *"$TARGET"* ]]; then
                    echo "$reverse" | sed 's/\.$//' >> "$dns_output"
                fi
            done
        fi
    fi
    
    # Combine all outputs
    echo -e "${YELLOW}Combining results...${NC}"
    touch "$combined_output"
    
    if [[ -f "$amass_output" ]]; then
        cat "$amass_output" >> "$combined_output"
    fi
    
    if [[ -f "$subfinder_output" ]]; then
        cat "$subfinder_output" >> "$combined_output"
    fi
    
    if [[ -f "$assetfinder_output" ]]; then
        cat "$assetfinder_output" >> "$combined_output"
    fi
    
    if [[ -f "$dns_output" ]]; then
        cat "$dns_output" >> "$combined_output"
    fi
    
    # Sort and remove duplicates
    sort "$combined_output" | uniq > "$unique_output"
    
    local subdomain_count=$(wc -l < "$unique_output")
    echo -e "${GREEN}Found ${BLUE}$subdomain_count${GREEN} unique subdomains for ${BLUE}$TARGET${NC}"
    
    # Convert to JSON if needed
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        local json_output="$OUTPUT_DIR/subdomains/subdomains.json"
        jq -R -s 'split("\n") | map(select(length > 0)) | {subdomains: .}' "$unique_output" > "$json_output"
        echo -e "${GREEN}Results saved to ${BLUE}$json_output${NC}"
    else
        echo -e "${GREEN}Results saved to ${BLUE}$unique_output${NC}"
    fi
    
    local end_time=$(date +%s)
    print_elapsed_time $start_time $end_time
    
    # If interactive mode, prompt to continue
    if [[ -z "$SCAN_TYPE" || "$SCAN_TYPE" == "subdomain" ]]; then
        echo -e "Press Enter to return to the main menu..."
        read
        show_menu
    fi
}
