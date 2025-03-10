#!/bin/bash

# Directory enumeration module for BountyX

# Run directory enumeration
run_dir_enum() {
    echo -e "${GREEN}Running Directory Enumeration against ${BLUE}$TARGET${NC}"
    
    local start_time=$(date +%s)
    
    setup_tor
    
    # Create directory enumeration output directory
    mkdir -p "$OUTPUT_DIR/directories"
    
    local target_list="$OUTPUT_DIR/directories/targets.txt"
    local target_type=$(get_target_type "$TARGET")
    
    # Determine targets for directory enumeration
    if [[ "$target_type" == "domain" ]]; then
        # Use live hosts if available
        if [[ -f "$OUTPUT_DIR/livehosts/alive_hosts.txt" ]]; then
            cp "$OUTPUT_DIR/livehosts/alive_hosts.txt" "$target_list"
            echo -e "${YELLOW}Using live hosts from previous scan...${NC}"
        else
            echo "http://$TARGET" > "$target_list"
            echo "https://$TARGET" >> "$target_list"
            echo -e "${YELLOW}No live hosts found, using main target with http and https...${NC}"
        fi
    else
        # For IP addresses
        echo "http://$TARGET" > "$target_list"
        echo "https://$TARGET" >> "$target_list"
    fi
    
    # Use the wordlists from the project directory or default to common ones
    local dir_wordlist="$SCRIPT_DIR/wordlists/directories.txt"
    local files_wordlist="$SCRIPT_DIR/wordlists/sensitive_files.txt"
    
    # If wordlists don't exist, use default ones
    if [[ ! -f "$dir_wordlist" ]]; then
        if [[ -f "/usr/share/wordlists/dirb/common.txt" ]]; then
            dir_wordlist="/usr/share/wordlists/dirb/common.txt"
        elif [[ -f "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt" ]]; then
            dir_wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
        else
            echo -e "${RED}No directory wordlist found. Please create one at $dir_wordlist${NC}"
            return 1
        fi
    fi
    
    if [[ ! -f "$files_wordlist" ]]; then
        # Create a small list of sensitive files
        cat > "$files_wordlist" << EOF
.git/HEAD
.env
.htaccess
robots.txt
sitemap.xml
config.php
wp-config.php
.DS_Store
backup.zip
database.sql
credentials.txt
password.txt
admin
login
dashboard
phpinfo.php
test.php
EOF
        echo -e "${YELLOW}Created a basic sensitive files wordlist at $files_wordlist${NC}"
    fi
    
    # Run different directory enumeration tools based on availability
    local combined_results="$OUTPUT_DIR/directories/combined_results.txt"
    > "$combined_results" # Create or truncate file
    
    # Scan each target
    while read -r url; do
        echo -e "${BLUE}Scanning $url${NC}"
        
        # Run ffuf if available
        if command_exists "ffuf"; then
            echo -e "${YELLOW}Running ffuf...${NC}"
            local ffuf_output="$OUTPUT_DIR/directories/ffuf_$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g').json"
            
            # Run ffuf with directory wordlist
            ffuf -u "$url/FUZZ" -w "$dir_wordlist" -mc 200,201,202,203,204,301,302,307,401,403,405 -o "$ffuf_output" -of json $TOR_PROXY
            
            # Extract results from ffuf output
            if [[ -f "$ffuf_output" ]]; then
                echo -e "${YELLOW}Extracting ffuf results...${NC}"
                jq -r '.results[] | "\(.url) [\(.status)]"' "$ffuf_output" >> "$combined_results"
            fi
            
            # Run ffuf with sensitive files wordlist
            local ffuf_files_output="$OUTPUT_DIR/directories/ffuf_files_$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g').json"
            ffuf -u "$url/FUZZ" -w "$files_wordlist" -mc 200,201,202,203,204,301,302,307,401,403,405 -o "$ffuf_files_output" -of json $TOR_PROXY
            
            # Extract results from ffuf files output
            if [[ -f "$ffuf_files_output" ]]; then
                echo -e "${YELLOW}Extracting ffuf sensitive files results...${NC}"
                jq -r '.results[] | "\(.url) [\(.status)]"' "$ffuf_files_output" >> "$combined_results"
            fi
        else
            echo -e "${YELLOW}ffuf not found, trying alternative tools...${NC}"
        fi
        
        # Run dirsearch if available and ffuf is not
        if ! command_exists "ffuf" && command_exists "dirsearch"; then
            echo -e "${YELLOW}Running dirsearch...${NC}"
            local dirsearch_output="$OUTPUT_DIR/directories/dirsearch_$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g').txt"
            
            python3 $(which dirsearch) -u "$url" -w "$dir_wordlist" -e php,html,js,txt -o "$dirsearch_output" $TOR_PROXY
            
            # Extract results from dirsearch output
            if [[ -f "$dirsearch_output" ]]; then
                grep -v "^$\|^#" "$dirsearch_output" >> "$combined_results"
            fi
            
            # Run dirsearch with sensitive files
            local dirsearch_files_output="$OUTPUT_DIR/directories/dirsearch_files_$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g').txt"
            python3 $(which dirsearch) -u "$url" -w "$files_wordlist" -o "$dirsearch_files_output" $TOR_PROXY
            
            # Extract results from dirsearch files output
            if [[ -f "$dirsearch_files_output" ]]; then
                grep -v "^$\|^#" "$dirsearch_files_output" >> "$combined_results"
            fi
        fi
        
        # Run gobuster if neither ffuf nor dirsearch is available
        if ! command_exists "ffuf" && ! command_exists "dirsearch" && command_exists "gobuster"; then
            echo -e "${YELLOW}Running gobuster...${NC}"
            local gobuster_output="$OUTPUT_DIR/directories/gobuster_$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g').txt"
            
            gobuster dir -u "$url" -w "$dir_wordlist" -o "$gobuster_output" $TOR_PROXY
            
            # Extract results from gobuster output
            if [[ -f "$gobuster_output" ]]; then
                cat "$gobuster_output" >> "$combined_results"
            fi
            
            # Run gobuster with sensitive files
            local gobuster_files_output="$OUTPUT_DIR/directories/gobuster_files_$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g').txt"
            gobuster dir -u "$url" -w "$files_wordlist" -o "$gobuster_files_output" $TOR_PROXY
            
            # Extract results from gobuster files output
            if [[ -f "$gobuster_files_output" ]]; then
                cat "$gobuster_files_output" >> "$combined_results"
            fi
        fi
        
        # Fallback to basic curl scanning if no directory enumeration tools are available
        if ! command_exists "ffuf" && ! command_exists "dirsearch" && ! command_exists "gobuster"; then
            echo -e "${YELLOW}No directory scanning tools found, using basic curl method...${NC}"
            local curl_output="$OUTPUT_DIR/directories/curl_$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g').txt"
            
            echo -e "${BLUE}Performing basic directory scan with curl...${NC}"
            while read -r directory; do
                if [[ -n "$directory" && ! "$directory" =~ ^# ]]; then
                    local target_url="${url}/${directory}"
                    local status=$(curl -s -o /dev/null -w "%{http_code}" "$target_url")
                    
                    if [[ "$status" != "404" ]]; then
                        echo "$target_url [$status]" >> "$curl_output"
                    fi
                fi
            done < "$dir_wordlist"
            
            # Check sensitive files
            echo -e "${BLUE}Checking sensitive files with curl...${NC}"
            while read -r file; do
                if [[ -n "$file" && ! "$file" =~ ^# ]]; then
                    local target_url="${url}/${file}"
                    local status=$(curl -s -o /dev/null -w "%{http_code}" "$target_url")
                    
                    if [[ "$status" != "404" ]]; then
                        echo "$target_url [$status]" >> "$curl_output"
                    fi
                fi
            done < "$files_wordlist"
            
            # Add results to combined results
            if [[ -f "$curl_output" ]]; then
                cat "$curl_output" >> "$combined_results"
            fi
        fi
        
    done < "$target_list"
    
    # Sort and deduplicate results
    sort "$combined_results" | uniq > "$OUTPUT_DIR/directories/unique_results.txt"
    
    # Convert to JSON if needed
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        echo -e "${YELLOW}Converting results to JSON...${NC}"
        local json_output="$OUTPUT_DIR/directories/directories.json"
        
        # Create JSON structure
        echo "{\"directory_scan\": [" > "$json_output"
        local first=true
        
        while read -r line; do
            if [[ -n "$line" ]]; then
                if $first; then
                    first=false
                else
                    echo "," >> "$json_output"
                fi
                
                # Extract URL and status code
                local url=$(echo "$line" | grep -oP '^.+(?= \[\d+\])' || echo "$line")
                local status=$(echo "$line" | grep -oP '\[(\d+)\]' | grep -oP '\d+' || echo "unknown")
                
                echo "{\"url\": \"$url\", \"status\": \"$status\"}" >> "$json_output"
            fi
        done < "$OUTPUT_DIR/directories/unique_results.txt"
        
        echo "]}" >> "$json_output"
    fi
    
    local end_time=$(date +%s)
    print_elapsed_time $start_time $end_time
    
    echo -e "${GREEN}Directory enumeration completed! Results saved to ${BLUE}$OUTPUT_DIR/directories/${NC}"
    
    # If interactive mode, prompt to continue
    if [[ -z "$SCAN_TYPE" || "$SCAN_TYPE" == "direnum" ]]; then
        echo -e "Press Enter to return to the main menu..."
        read
        show_menu
    fi
}
