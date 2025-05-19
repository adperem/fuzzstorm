# FuzzStorm

FuzzStorm is an advanced web fuzzing tool developed in Python to discover resources, subdomains, and potential vulnerabilities in web applications.

## Features

- 🔍 **Flexible Scanning**: normal, recursive, and extension-based
- 🔄 **Content Scanning**: extracts and tests URLs found in successful responses
- 🌐 **Subdomain Discovery**
- 🧪 **Automatic Testing of Alternative HTTP Methods**
- 🧹 **Automatic Wordlist Cleaning**
- 📊 **Progress Bars with Real-time Statistics**
- 🔒 **Security Analysis**: missing headers and vulnerability patterns
- 🌍 **Privacy**: support for proxies
- 🎨 **Colored Output** for better readability
- 🔍 **Soft 404 Detection** to identify false positives
- 🧩 **Advanced Filtering Options** to process results

## Installation

```bash
# Clone the repository
git clone https://github.com/adperem/fuzzstorm.git
cd fuzzstorm

# Install dependencies
pip install -r requirements.txt
```

## Basic Usage

```bash
python fuzzstorm.py -u http://example.com -w wordlists/common.txt
```

## Available Options

```
  -h, --help            Show help message
  -u URL, --url URL     Target URL (required)
  -w WORDLIST, --wordlist WORDLIST
                        Path to wordlist file (required)
  -e EXTENSIONS, --extensions EXTENSIONS
                        File extensions to look for (comma-separated)
  -t THREADS, --threads THREADS
                        Number of threads (default: 10)
  -d DELAY, --delay DELAY
                        Delay between requests in seconds (default: 0)
  -o OUTPUT, --output OUTPUT
                        Output file to save results
  --format {txt,json,csv}
                        Output format: txt, json, or csv (default: txt)
  --max-depth MAX_DEPTH
                        Maximum depth for recursive scanning (default: 3)
  --no-test-methods     Disable testing of alternative HTTP methods
  --subdomains          Enable subdomain search
  --no-content-scan     Disable content scanning for new URLs
  --proxy PROXY         Use proxy for requests
  --security-analysis   Enable security analysis
  --no-report           Disable automatic report generation
  --no-detect-soft-404  Disable soft 404 page detection (enabled by default)
  --soft-404-threshold  Similarity threshold for soft 404 detection (0.0-1.0, default: 0.9)
  --debug               Enable detailed debug messages
```

### Matcher Options
```
  -mc, --match-code     Match HTTP status codes, or "all" for everything
                        (default: 200-299,301,302,307,401,403,405,500)
  -ml, --match-lines    Match number of lines in response (e.g. ">10", "<100", "=50")
  -mmode, --match-mode  Matcher set operator. Either of: and, or (default: or)
  -mr, --match-regexp   Match regexp in response content
  -ms, --match-size     Match HTTP response size in bytes (e.g. ">1000", "<5000")
  -mt, --match-time     Match response time in milliseconds (e.g. ">100" or "<100")
  -mw, --match-words    Match number of words in response (e.g. ">100", "<1000")
```

### Filter Options
```
  -fc, --filter-code    Filter HTTP status codes from response
  -fl, --filter-lines   Filter by number of lines in response
  -fmode, --filter-mode Filter set operator. Either of: and, or (default: or)
  -fr, --filter-regexp  Filter regexp
  -fs, --filter-size    Filter HTTP response size
  -ft, --filter-time    Filter by response time in milliseconds (e.g.: >100 or <100)
  -fw, --filter-words   Filter by number of words in response
```

## Examples

### Basic Scan
```bash
python fuzzstorm.py -u http://example.com -w wordlists/common.txt
```

### Comprehensive Scan with Security Analysis
```bash
python fuzzstorm.py -u http://example.com -w wordlists/common.txt --security-analysis --subdomains -t 20
```

### Find Files with Specific Extensions
```bash
python fuzzstorm.py -u http://example.com -w wordlists/common.txt -e php,txt,bak,old,backup
```

### Use a Proxy
```bash
python fuzzstorm.py -u http://example.com -w wordlists/common.txt --proxy http://proxy:8080
```

### Export Results in JSON Format
```bash
python fuzzstorm.py -u http://example.com -w wordlists/common.txt -o results.json --format json
```

### Filter Results to Show Only Certain Status Codes
```bash
python fuzzstorm.py -u http://example.com -w wordlists/common.txt -mc 200,403
```

## Key Features

### Content Scanning
FuzzStorm automatically analyzes the content of pages with 200 status codes to extract new URLs and expand the scope of the scan, discovering content that doesn't appear in wordlists.

### Security Analysis
When activated with `--security-analysis`, FuzzStorm checks for:
- Missing security headers (HSTS, CSP, X-Frame-Options, etc.)
- Vulnerability patterns in responses (SQL errors, internal paths, exposed tokens)

### Soft 404 Detection
FuzzStorm can detect "soft 404" pages - pages that return a 200 status code but are actually not found pages. This helps reduce false positives in your scan results.

### Advanced Filtering
After scanning, you can filter results using various criteria like status codes, response size, content patterns, and more to focus on what matters most to your assessment.

### Enhanced Visualization
Results are displayed with color-coded status codes and tabulated output for better readability, allowing you to quickly identify important resources.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 