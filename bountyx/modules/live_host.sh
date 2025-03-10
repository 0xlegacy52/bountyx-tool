#!/bin/bash

# Live host detection module for BountyX

# Run live host detection
run_live_host() {
    echo -e "${GREEN}Running Live Host Detection against ${BLUE}$TARGET${NC}"
    
    local start_time=$(date +%s)
    local target_type=$(get_target_type "$TARGET")
    
    setup_tor
    
    # Create live hosts output directory
    mkdir -p "$OUTPUT_DIR/livehosts"
    
    local target_list="$OUTPUT_DIR/livehosts/targets.txt"
    
    # Determine targets for live host detection
    if [[ "$target_type" == "domain" ]]; then
        # If subdomains are available, use them
        if [[ -f "$OUTPUT_DIR/subdomains/unique_subdomains.txt" ]]; then
            cp "$OUTPUT_DIR/subdomains/unique_subdomains.txt" "$target_list"
            echo -e "${YELLOW}Using discovered subdomains for live host detection...${NC}"
        else
            # If no subdomains, just use the main target
            echo "$TARGET" > "$target_list"
            echo -e "${YELLOW}No subdomain results found, using main target...${NC}"
        fi
    else
        # For IP addresses or CIDR
        echo "$TARGET" > "$target_list"
    fi
    
    local httpx_output="$OUTPUT_DIR/livehosts/httpx_output.txt"
    local httprobe_output="$OUTPUT_DIR/livehosts/httprobe_output.txt"
    local combined_output="$OUTPUT_DIR/livehosts/alive_hosts.txt"
    
    # Use httpx if available
    if command_exists "httpx"; then
        echo -e "${YELLOW}Running httpx...${NC}"
        cat "$target_list" | httpx -silent -o "$httpx_output" $TOR_PROXY
    else
        echo -e "${YELLOW}httpx not found, skipping...${NC}"
    fi
    
    # Use httprobe if available
    if command_exists "httprobe"; then
        echo -e "${YELLOW}Running httprobe...${NC}"
        cat "$target_list" | httprobe > "$httprobe_output"
    else
        echo -e "${YELLOW}httprobe not found, skipping...${NC}"
    fi
    
    # If neither httpx nor httprobe is available, use curl
    if ! command_exists "httpx" && ! command_exists "httprobe"; then
        echo -e "${YELLOW}Using curl for basic host detection...${NC}"
        local curl_output="$OUTPUT_DIR/livehosts/curl_output.txt"
        > "$curl_output"
        
        while read -r domain; do
            echo -e "${BLUE}Checking $domain...${NC}"
            # Try HTTP
            if curl -s --connect-timeout 5 "http://$domain" -o /dev/null; then
                echo "http://$domain" >> "$curl_output"
                echo -e "${GREEN}http://$domain is alive${NC}"
            fi
            
            # Try HTTPS
            if curl -s --connect-timeout 5 -k "https://$domain" -o /dev/null; then
                echo "https://$domain" >> "$curl_output"
                echo -e "${GREEN}https://$domain is alive${NC}"
            fi
        done < "$target_list"
        
        if [[ -f "$curl_output" ]]; then
            cp "$curl_output" "$combined_output"
        fi
    else
        # Combine httpx and httprobe outputs
        > "$combined_output"
        
        if [[ -f "$httpx_output" ]]; then
            cat "$httpx_output" >> "$combined_output"
        fi
        
        if [[ -f "$httprobe_output" ]]; then
            cat "$httprobe_output" >> "$combined_output"
        fi
        
        # Sort and remove duplicates
        sort "$combined_output" | uniq > "$OUTPUT_DIR/livehosts/unique_alive_hosts.txt"
        mv "$OUTPUT_DIR/livehosts/unique_alive_hosts.txt" "$combined_output"
    fi
    
    local host_count=$(wc -l < "$combined_output")
    echo -e "${GREEN}Found ${BLUE}$host_count${GREEN} live hosts for ${BLUE}$TARGET${NC}"
    
    # Convert to JSON if needed
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        local json_output="$OUTPUT_DIR/livehosts/live_hosts.json"
        jq -R -s 'split("\n") | map(select(length > 0)) | {live_hosts: .}' "$combined_output" > "$json_output"
        echo -e "${GREEN}Results saved to ${BLUE}$json_output${NC}"
    else
        echo -e "${GREEN}Results saved to ${BLUE}$combined_output${NC}"
    fi
    
    local end_time=$(date +%s)
    print_elapsed_time $start_time $end_time
    
    # If interactive mode, prompt to continue
    if [[ -z "$SCAN_TYPE" || "$SCAN_TYPE" == "livehost" ]]; then
        echo -e "Press Enter to return to the main menu..."
        read
        show_menu
    fi
}
