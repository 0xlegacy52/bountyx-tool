#!/bin/bash

# Vulnerability scanning module for BountyX

# Run vulnerability scanning
run_vuln_scan() {
    echo -e "${GREEN}Running Vulnerability Scanning against ${BLUE}$TARGET${NC}"
    
    local start_time=$(date +%s)
    
    setup_tor
    
    # Create vulnerability scanning output directory
    mkdir -p "$OUTPUT_DIR/vulnerabilities"
    
    local target_list="$OUTPUT_DIR/vulnerabilities/targets.txt"
    
    # Determine targets for vulnerability scanning
    if [[ -f "$OUTPUT_DIR/livehosts/alive_hosts.txt" ]]; then
        cp "$OUTPUT_DIR/livehosts/alive_hosts.txt" "$target_list"
        echo -e "${YELLOW}Using live hosts from previous scan...${NC}"
    else
        local target_type=$(get_target_type "$TARGET")
        if [[ "$target_type" == "domain" ]]; then
            echo "http://$TARGET" > "$target_list"
            echo "https://$TARGET" >> "$target_list"
        else
            echo "http://$TARGET" > "$target_list"
            echo "https://$TARGET" >> "$target_list"
        fi
        echo -e "${YELLOW}No live hosts found, using main target...${NC}"
    fi
    
    local nuclei_output="$OUTPUT_DIR/vulnerabilities/nuclei_output.txt"
    local nuclei_json_output="$OUTPUT_DIR/vulnerabilities/nuclei_output.json"
    local manual_checks_output="$OUTPUT_DIR/vulnerabilities/manual_checks.txt"
    local combined_output="$OUTPUT_DIR/vulnerabilities/all_vulnerabilities.txt"
    
    # Run nuclei if available
    if command_exists "nuclei"; then
        echo -e "${YELLOW}Running nuclei for vulnerability scanning...${NC}"
        
        nuclei -l "$target_list" -o "$nuclei_output" -json -j "$nuclei_json_output" $TOR_PROXY
        
        if [[ -f "$nuclei_output" ]]; then
            echo -e "${GREEN}Nuclei scan completed. Results saved to ${BLUE}$nuclei_output${NC}"
        else
            echo -e "${RED}Nuclei scan failed or found no results.${NC}"
        fi
    else
        echo -e "${YELLOW}nuclei not found, skipping automated vulnerability scanning...${NC}"
    fi
    
    # Perform manual checks for common vulnerabilities
    echo -e "${YELLOW}Performing manual checks for common vulnerabilities...${NC}"
    > "$manual_checks_output"
    
    while read -r url; do
        echo -e "${BLUE}Checking $url for common vulnerabilities...${NC}"
        
        # Check for robots.txt
        echo -e "${YELLOW}Checking robots.txt...${NC}"
        local robots_url="${url}/robots.txt"
        local robots_output=$(curl -s --connect-timeout 5 "$robots_url")
        
        if [[ -n "$robots_output" ]]; then
            echo -e "${GREEN}Found robots.txt at $robots_url${NC}"
            echo "robots.txt found at $robots_url" >> "$manual_checks_output"
            echo "Content:" >> "$manual_checks_output"
            echo "$robots_output" >> "$manual_checks_output"
            echo "" >> "$manual_checks_output"
        fi
        
        # Check for .env file
        echo -e "${YELLOW}Checking .env file...${NC}"
        local env_url="${url}/.env"
        local env_status=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "$env_url")
        
        if [[ "$env_status" == "200" ]]; then
            echo -e "${RED}Found .env file at $env_url - CRITICAL!${NC}"
            echo "CRITICAL: .env file exposed at $env_url" >> "$manual_checks_output"
            echo "" >> "$manual_checks_output"
        fi
        
        # Check for .git directory
        echo -e "${YELLOW}Checking .git directory...${NC}"
        local git_url="${url}/.git/HEAD"
        local git_status=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "$git_url")
        
        if [[ "$git_status" == "200" ]]; then
            echo -e "${RED}Found .git directory at ${url}/.git/ - CRITICAL!${NC}"
            echo "CRITICAL: .git directory exposed at ${url}/.git/" >> "$manual_checks_output"
            echo "" >> "$manual_checks_output"
        fi
        
        # Check for server headers
        echo -e "${YELLOW}Checking server headers...${NC}"
        local headers=$(curl -s -I --connect-timeout 5 "$url")
        
        if [[ -n "$headers" ]]; then
            echo "Headers for $url:" >> "$manual_checks_output"
            echo "$headers" >> "$manual_checks_output"
            echo "" >> "$manual_checks_output"
            
            # Check for specific headers that might reveal information
            if echo "$headers" | grep -i "Server:" | grep -i -E "Apache/2.2|Apache/2.4|nginx/1.0|IIS/6.0|IIS/7.0"; then
                echo -e "${YELLOW}Server header reveals potentially outdated software${NC}"
                echo "WARNING: Server header reveals potentially outdated software" >> "$manual_checks_output"
            fi
            
            # Check for missing security headers
            if ! echo "$headers" | grep -i "X-XSS-Protection:"; then
                echo "WARNING: X-XSS-Protection header missing" >> "$manual_checks_output"
            fi
            
            if ! echo "$headers" | grep -i "Content-Security-Policy:"; then
                echo "WARNING: Content-Security-Policy header missing" >> "$manual_checks_output"
            fi
            
            if ! echo "$headers" | grep -i "X-Frame-Options:"; then
                echo "WARNING: X-Frame-Options header missing" >> "$manual_checks_output"
            fi
            
            if ! echo "$headers" | grep -i "X-Content-Type-Options:"; then
                echo "WARNING: X-Content-Type-Options header missing" >> "$manual_checks_output"
            fi
            
            echo "" >> "$manual_checks_output"
        fi
        
        # Basic SQLi check on a few common parameters
        echo -e "${YELLOW}Performing basic SQLi checks...${NC}"
        local sqli_params=("id" "page" "search" "q" "query" "user" "username" "pid")
        
        for param in "${sqli_params[@]}"; do
            local sqli_test_url="${url}?${param}=1%27"
            local sqli_output=$(curl -s --connect-timeout 5 "$sqli_test_url")
            
            if echo "$sqli_output" | grep -i -E "SQL syntax|mysql_fetch|ORA-|syntax error|microsoft SQL|postgresql"; then
                echo -e "${RED}Possible SQL injection found at $sqli_test_url${NC}"
                echo "CRITICAL: Possible SQL injection at $sqli_test_url" >> "$manual_checks_output"
                echo "" >> "$manual_checks_output"
            fi
        done
        
        # Basic XSS check
        echo -e "${YELLOW}Performing basic XSS checks...${NC}"
        local xss_params=("search" "q" "query" "id" "page" "text")
        
        for param in "${xss_params[@]}"; do
            local xss_test_url="${url}?${param}=<script>alert(1)</script>"
            local xss_output=$(curl -s --connect-timeout 5 "$xss_test_url")
            
            if echo "$xss_output" | grep -i "<script>alert(1)</script>"; then
                echo -e "${RED}Possible XSS found at $xss_test_url${NC}"
                echo "CRITICAL: Possible XSS at $xss_test_url" >> "$manual_checks_output"
                echo "" >> "$manual_checks_output"
            fi
        done
        
    done < "$target_list"
    
    # Combine results
    > "$combined_output"
    
    if [[ -f "$nuclei_output" ]]; then
        cat "$nuclei_output" >> "$combined_output"
    fi
    
    if [[ -f "$manual_checks_output" ]]; then
        cat "$manual_checks_output" >> "$combined_output"
    fi
    
    # Convert manual checks to JSON if needed
    if [[ "$OUTPUT_FORMAT" == "json" && -f "$manual_checks_output" ]]; then
        local manual_json_output="$OUTPUT_DIR/vulnerabilities/manual_checks.json"
        
        # This is a simple approach - a more complex parser would be better
        echo "{\"manual_checks\": [" > "$manual_json_output"
        local first=true
        
        # Read the file in chunks separated by blank lines
        awk 'BEGIN {RS="\n\n"; ORS="\n\n"} {print}' "$manual_checks_output" | while read -r chunk; do
            if [[ -n "$chunk" ]]; then
                if $first; then
                    first=false
                else
                    echo "," >> "$manual_json_output"
                fi
                
                # Get the first line as a title
                local title=$(echo "$chunk" | head -n 1)
                # Get the rest as content
                local content=$(echo "$chunk" | tail -n +2)
                
                # Clean the strings for JSON
                title=$(echo "$title" | sed 's/"/\\"/g')
                content=$(echo "$content" | sed 's/"/\\"/g' | tr '\n' ' ')
                
                echo "{\"title\": \"$title\", \"content\": \"$content\"}" >> "$manual_json_output"
            fi
        done
        
        echo "]}" >> "$manual_json_output"
    fi
    
    local end_time=$(date +%s)
    print_elapsed_time $start_time $end_time
    
    echo -e "${GREEN}Vulnerability scanning completed! Results saved to ${BLUE}$OUTPUT_DIR/vulnerabilities/${NC}"
    
    # If interactive mode, prompt to continue
    if [[ -z "$SCAN_TYPE" || "$SCAN_TYPE" == "vulnscan" ]]; then
        echo -e "Press Enter to return to the main menu..."
        read
        show_menu
    fi
}
