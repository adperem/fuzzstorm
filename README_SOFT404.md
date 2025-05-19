# Soft 404 Detector

This script allows detecting HTTP 200 responses that are actually "soft 404" error pages. "Soft 404" pages return a 200 (OK) status code instead of the correct 404 (Not Found) when accessing non-existent resources.

## What are Soft 404s?

Soft 404s are error pages that:
- Return HTTP status code 200 (OK)
- But actually indicate that the requested content does not exist
- Can be confusing during the content discovery process

## Detector Features

- Automatically generates 404 page signatures by requesting random non-existent URLs
- Compares pages through content similarity analysis
- Detects pages containing typical error messages ("not found", "does not exist", etc.)
- Allows adjusting the detection threshold

## Usage

```
python detect_soft_404.py -u https://example.com -f urls.txt
```

### Parameters

- `-u, --url`: Base URL of the site to analyze
- `-f, --file`: File with list of URLs to verify
- `-t, --threshold`: Similarity threshold (0.0-1.0), default 0.9
- `--timeout`: Maximum time for HTTP requests
- `--user-agent`: Custom User-Agent
- `--proxy`: Proxy for requests (e.g.: http://127.0.0.1:8080)
- `-o, --output`: File to save results

## Integration with FuzzStorm

To use with FuzzStorm:

1. Run FuzzStorm and filter only 200 responses:
```
python fuzzstorm.py -u https://example.com -w wordlist.txt -fc '100-199,201-599'
```

2. Save URLs with code 200 to a file:
```
python fuzzstorm.py -u https://example.com -o urls_200.txt --match-code 200
```

3. Run the soft 404 detector:
```
python detect_soft_404.py -u https://example.com -f urls_200.txt -o results.txt
```

## Output

The script will generate output like this:

```
[*] Verifying 100 URLs to detect soft 404s...
[SOFT 404] https://example.com/non-existent-page
[REAL 200] https://example.com/real-page

[*] Summary:
    - URLs verified: 100
    - Soft 404s detected: 20
    - Real 200 URLs: 80
```

If an output file is specified, the classified URLs will be saved in two sections:
- SOFT 404s: URLs detected as error pages
- REAL 200s: URLs with real content 