#!/bin/bash

# Website screenshots module for BountyX

# Run website screenshots
run_screenshot() {
    echo -e "${GREEN}Running Website Screenshots against ${BLUE}$TARGET${NC}"
    
    local start_time=$(date +%s)
    
    setup_tor
    
    # Create screenshots output directory
    mkdir -p "$OUTPUT_DIR/screenshots"
    
    local target_list="$OUTPUT_DIR/screenshots/targets.txt"
    
    # Determine targets for screenshots
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
    
    local screenshot_results="$OUTPUT_DIR/screenshots/results.txt"
    
    # Take screenshots using gowitness if available
    if command_exists "gowitness"; then
        echo -e "${YELLOW}Using gowitness for screenshots...${NC}"
        
        # Create a gowitness directory
        local gowitness_dir="$OUTPUT_DIR/screenshots/gowitness"
        mkdir -p "$gowitness_dir"
        
        # Run gowitness
        gowitness file -f "$target_list" -o "$gowitness_dir" $TOR_PROXY
        
        # Create a summary of the screenshots
        echo "Screenshots taken with gowitness at $(date)" > "$screenshot_results"
        echo "Results saved in $gowitness_dir" >> "$screenshot_results"
        ls -la "$gowitness_dir" >> "$screenshot_results"
        
        echo -e "${GREEN}Gowitness screenshots completed. Results saved to ${BLUE}$gowitness_dir${NC}"
    elif command_exists "aquatone"; then
        # Use aquatone if gowitness is not available
        echo -e "${YELLOW}Using aquatone for screenshots...${NC}"
        
        # Create an aquatone directory
        local aquatone_dir="$OUTPUT_DIR/screenshots/aquatone"
        mkdir -p "$aquatone_dir"
        
        # Run aquatone
        cat "$target_list" | aquatone -out "$aquatone_dir" $TOR_PROXY
        
        # Create a summary of the screenshots
        echo "Screenshots taken with aquatone at $(date)" > "$screenshot_results"
        echo "Results saved in $aquatone_dir" >> "$screenshot_results"
        ls -la "$aquatone_dir" >> "$screenshot_results"
        
        echo -e "${GREEN}Aquatone screenshots completed. Results saved to ${BLUE}$aquatone_dir${NC}"
    else
        # If neither gowitness nor aquatone is available, use a very basic approach with cutycapt or wkhtmltoimage
        if command_exists "cutycapt"; then
            echo -e "${YELLOW}Using cutycapt for screenshots...${NC}"
            
            # Create a screenshots directory
            local cutycapt_dir="$OUTPUT_DIR/screenshots/cutycapt"
            mkdir -p "$cutycapt_dir"
            
            # Take screenshots with cutycapt
            while read -r url; do
                local filename=$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g')
                echo -e "${BLUE}Taking screenshot of $url${NC}"
                cutycapt --url="$url" --out="$cutycapt_dir/$filename.png"
            done < "$target_list"
            
            # Create a summary of the screenshots
            echo "Screenshots taken with cutycapt at $(date)" > "$screenshot_results"
            echo "Results saved in $cutycapt_dir" >> "$screenshot_results"
            ls -la "$cutycapt_dir" >> "$screenshot_results"
            
            echo -e "${GREEN}Cutycapt screenshots completed. Results saved to ${BLUE}$cutycapt_dir${NC}"
        elif command_exists "wkhtmltoimage"; then
            echo -e "${YELLOW}Using wkhtmltoimage for screenshots...${NC}"
            
            # Create a screenshots directory
            local wkhtml_dir="$OUTPUT_DIR/screenshots/wkhtmltoimage"
            mkdir -p "$wkhtml_dir"
            
            # Take screenshots with wkhtmltoimage
            while read -r url; do
                local filename=$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g')
                echo -e "${BLUE}Taking screenshot of $url${NC}"
                wkhtmltoimage "$url" "$wkhtml_dir/$filename.png"
            done < "$target_list"
            
            # Create a summary of the screenshots
            echo "Screenshots taken with wkhtmltoimage at $(date)" > "$screenshot_results"
            echo "Results saved in $wkhtml_dir" >> "$screenshot_results"
            ls -la "$wkhtml_dir" >> "$screenshot_results"
            
            echo -e "${GREEN}Wkhtmltoimage screenshots completed. Results saved to ${BLUE}$wkhtml_dir${NC}"
        else
            echo -e "${YELLOW}No dedicated screenshot tools found. Using Python-based fallback...${NC}"
            
            # Create a Python screenshots directory
            local python_dir="$OUTPUT_DIR/screenshots/python_screenshots"
            mkdir -p "$python_dir"
            
            # Create a Python script for taking screenshots
            local screenshot_script="$OUTPUT_DIR/screenshots/take_screenshot.py"
            cat > "$screenshot_script" << 'EOF'
#!/usr/bin/env python3
import sys
import os
import urllib.request
import urllib.parse
import time
from datetime import datetime
import json

def take_screenshot(url, output_path):
    try:
        # Create a simple HTML file with an iframe
        html_content = f"""
        <html>
        <head>
            <title>BountyX Screenshot</title>
            <style>
                body, html {{
                    margin: 0;
                    padding: 0;
                    height: 100%;
                    overflow: hidden;
                }}
                .screenshot-container {{
                    width: 100%;
                    height: 100%;
                    position: relative;
                }}
                .timestamp {{
                    position: absolute;
                    bottom: 10px;
                    right: 10px;
                    background: rgba(0,0,0,0.7);
                    color: white;
                    padding: 5px;
                    border-radius: 3px;
                    font-family: monospace;
                }}
                iframe {{
                    width: 100%;
                    height: 100%;
                    border: none;
                }}
            </style>
        </head>
        <body>
            <div class="screenshot-container">
                <iframe src="{url}" sandbox="allow-same-origin allow-scripts"></iframe>
                <div class="timestamp">BountyX Screenshot - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
            </div>
        </body>
        </html>
        """
        
        with open(output_path, 'w') as f:
            f.write(html_content)
        
        print(f"Created HTML screenshot for {url} at {output_path}")
        return True
    except Exception as e:
        print(f"Error taking screenshot of {url}: {str(e)}")
        return False

def main():
    if len(sys.argv) < 3:
        print("Usage: python take_screenshot.py <url> <output_dir>")
        sys.exit(1)
    
    url = sys.argv[1]
    output_dir = sys.argv[2]
    
    # Generate filename from URL
    filename = urllib.parse.quote_plus(url).replace('.', '_').replace('/', '_')
    output_path = os.path.join(output_dir, f"{filename}.html")
    
    result = take_screenshot(url, output_path)
    
    # Create a JSON result for this screenshot
    result_json = {
        "url": url,
        "timestamp": datetime.now().isoformat(),
        "success": result,
        "output_file": output_path
    }
    
    print(json.dumps(result_json))

if __name__ == "__main__":
    main()
EOF
            
            # Make the script executable
            chmod +x "$screenshot_script"
            
            # Create the JSON results
            echo "{\"screenshots\": []}" > "$OUTPUT_DIR/screenshots/screenshots.json"
            
            # Take screenshots for each URL
            while read -r url; do
                echo -e "${BLUE}Taking screenshot of $url${NC}"
                local result=$(python3 "$screenshot_script" "$url" "$python_dir")
                
                # Update the JSON file
                local temp_file=$(mktemp)
                jq --argjson new "$(echo "$result" | grep -v "Created HTML screenshot")" '.screenshots += [$new]' "$OUTPUT_DIR/screenshots/screenshots.json" > "$temp_file"
                mv "$temp_file" "$OUTPUT_DIR/screenshots/screenshots.json"
            done < "$target_list"
            
            # Create a summary of the screenshots
            echo "Screenshots taken with Python fallback at $(date)" > "$screenshot_results"
            echo "Results saved in $python_dir" >> "$screenshot_results"
            ls -la "$python_dir" >> "$screenshot_results"
            
            echo -e "${GREEN}Python-based screenshots completed. Results saved to ${BLUE}$python_dir${NC}"
        fi
    fi
    
    # Convert to JSON if needed
    if [[ "$OUTPUT_FORMAT" == "json" && ! -f "$OUTPUT_DIR/screenshots/screenshots.json" ]]; then
        local json_output="$OUTPUT_DIR/screenshots/screenshots.json"
        
        echo "{\"screenshots\": {" > "$json_output"
        echo "  \"timestamp\": \"$(date)\", " >> "$json_output"
        echo "  \"tool\": \"$(command_exists gowitness && echo 'gowitness' || (command_exists aquatone && echo 'aquatone' || (command_exists cutycapt && echo 'cutycapt' || (command_exists wkhtmltoimage && echo 'wkhtmltoimage' || echo 'python_fallback'))))\", " >> "$json_output"
        echo "  \"targets\": [" >> "$json_output"
        
        local first=true
        while read -r url; do
            if $first; then
                first=false
            else
                echo "," >> "$json_output"
            fi
            echo "    \"$url\"" >> "$json_output"
        done < "$target_list"
        
        echo "  ]" >> "$json_output"
        echo "}}" >> "$json_output"
    fi
    
    local end_time=$(date +%s)
    print_elapsed_time $start_time $end_time
    
    echo -e "${GREEN}Screenshot process completed! Results saved to ${BLUE}$OUTPUT_DIR/screenshots/${NC}"
    
    # If interactive mode, prompt to continue
    if [[ -z "$SCAN_TYPE" || "$SCAN_TYPE" == "screenshot" ]]; then
        echo -e "Press Enter to return to the main menu..."
        read
        show_menu
    fi
}
