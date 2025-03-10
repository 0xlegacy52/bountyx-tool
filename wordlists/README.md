# BountyX Wordlists

This directory contains wordlists used by BountyX for directory enumeration and sensitive file detection.

## Included Wordlists

- `directories.txt`: Contains common directory names for web fuzzing
- `sensitive_files.txt`: Contains potentially sensitive files to check for during scans

## Usage

These wordlists are automatically used by BountyX when running directory enumeration and vulnerability scanning modules.

## Customization

You can customize these wordlists to better suit your needs:

1. Add new entries to target specific technologies
2. Remove entries to make scans faster
3. Create specialized wordlists for particular targets

## Best Practices

- For more comprehensive scans, consider replacing these wordlists with larger ones like SecLists
- For faster scans, reduce the wordlist size by removing less common entries
- Create industry-specific wordlists for better results with specific targets

## Sources

The included wordlists are compiled from various sources and common findings in bug bounty programs.

## Adding Your Own Wordlists

You can add additional wordlists to this directory and modify the modules to use them:

1. Add your wordlist file (e.g., `custom_list.txt`)
2. Modify the appropriate module file (e.g., `modules/dir_enum.sh`)
3. Update the wordlist path variable to use your custom list

Example modification in a module:

```bash
# Original line
local dir_wordlist="$SCRIPT_DIR/wordlists/directories.txt"

# Modified to use your custom wordlist
local dir_wordlist="$SCRIPT_DIR/wordlists/custom_list.txt"
