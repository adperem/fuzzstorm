#!/usr/bin/env python3

import argparse
import re
import random
import string
import requests
from difflib import SequenceMatcher
from urllib.parse import urlparse, urljoin
import sys

class Soft404Detector:
    def __init__(self, target_url, threshold=0.9, timeout=10, user_agent=None, proxy=None, debug=False):
        """
        Initialize the soft 404 detector.
        
        Args:
            target_url (str): Base URL to test
            threshold (float): Similarity threshold to consider a page as soft 404
            timeout (int): HTTP request timeout
            user_agent (str): Custom User-Agent
            proxy (str): Proxy for requests
            debug (bool): If True, shows debug messages
        """
        self.debug = debug
        
        if self.debug:
            print(f"[DEBUG-S404] Initializing Soft404Detector with URL: {target_url}")
            print(f"[DEBUG-S404] Proxy configured: {proxy}")
            print(f"[DEBUG-S404] User-Agent: {user_agent}")
        
        self.target_url = target_url
        self.threshold = threshold
        self.timeout = timeout
        self.headers = {'User-Agent': user_agent or 'Mozilla/5.0 FuzzStorm Soft404Detector'}
        self.proxies = {'http': proxy, 'https': proxy} if proxy else None
        
        if self.debug:
            print(f"[DEBUG-S404] Generating 404 page signatures...")
        self.not_found_signatures = self._get_not_found_signatures()
        if self.debug:
            print(f"[DEBUG-S404] Signature generation completed: {len(self.not_found_signatures)} signatures")
        
    def _get_not_found_signatures(self):
        """Generate 404 page signatures by requesting random non-existent URLs"""
        signatures = []
        base_url = self._get_base_url()
        if self.debug:
            print(f"[DEBUG-S404] Base URL for signatures: {base_url}")
        
        # Generate 3 random non-existent URLs
        for i in range(3):
            random_path = ''.join(random.choices(string.ascii_lowercase + string.digits, k=20))
            random_url = urljoin(base_url, random_path)
            if self.debug:
                print(f"[DEBUG-S404] Generating signature {i+1}, random URL: {random_url}")
            
            try:
                if self.debug:
                    print(f"[DEBUG-S404] Sending request to {random_url}...")
                response = requests.get(
                    random_url, 
                    headers=self.headers,
                    proxies=self.proxies,
                    timeout=self.timeout,
                    allow_redirects=True
                )
                if self.debug:
                    print(f"[DEBUG-S404] Response received: HTTP {response.status_code}, {len(response.text)} characters")
                
                normalized = self._normalize_content(response.text)
                if self.debug:
                    print(f"[DEBUG-S404] Normalized content: {len(normalized)} characters")
                signatures.append(normalized)
                
                # Show normalized content preview
                if self.debug:
                    preview = normalized[:100] + "..." if len(normalized) > 100 else normalized
                    print(f"[DEBUG-S404] Preview of signature {i+1}: {preview}")
                
            except Exception as e:
                if self.debug:
                    print(f"[DEBUG-S404] Error getting signature {i+1}: {str(e)}")
                continue
        
        if self.debug:
            print(f"[DEBUG-S404] Generated signatures: {len(signatures)}")
        return signatures
    
    def _get_base_url(self):
        """Extract the base URL from the target"""
        parsed = urlparse(self.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}/"
        if self.debug:
            print(f"[DEBUG-S404] Extracted base URL: {base_url}")
        return base_url
    
    def _normalize_content(self, content):
        """Normalize HTML content for comparison"""
        # Remove whitespace and empty lines
        content = re.sub(r'\s+', ' ', content).strip()
        # Remove numbers and variable tokens
        content = re.sub(r'\d+', 'X', content)
        return content
    
    def _calculate_similarity(self, content1, content2):
        """Calculate similarity between two texts"""
        similarity = SequenceMatcher(None, content1, content2).ratio()
        return similarity
    
    def detect_soft_404(self, url):
        """
        Detect if a URL with 200 response is actually a soft 404.
        
        Args:
            url (str): URL to verify
            
        Returns:
            bool: True if it's a soft 404, False otherwise
        """
        if self.debug:
            print(f"[DEBUG-S404] Checking if {url} is soft 404...")
        
        # Check if URL is exactly the base URL or main page
        base_url = self._get_base_url().rstrip('/')
        if url.rstrip('/') == base_url:
            if self.debug:
                print(f"[DEBUG-S404] URL is the main page: {url} == {base_url}")
            return False
            
        try:
            if self.debug:
                print(f"[DEBUG-S404] Sending GET request to {url}")
            response = requests.get(
                url, 
                headers=self.headers,
                proxies=self.proxies,
                timeout=self.timeout,
                allow_redirects=True
            )
            
            # If not 200, it's not a soft 404 (it's an explicit error)
            if response.status_code != 200:
                if self.debug:
                    print(f"[DEBUG-S404] Not soft 404: status code {response.status_code} != 200")
                return False
            
            # Check for typical error page keywords in original content
            error_keywords = ['not found', 'page not found', '404', 'does not exist', 
                             'could not be found', 'no se ha encontrado', 'no encontrada']
            
            content_lower = response.text.lower()
            
            # Search for keywords in original content
            keyword_matches = []
            for keyword in error_keywords:
                if keyword in content_lower:
                    keyword_matches.append(keyword)
                    
            if keyword_matches:
                if self.debug:
                    print(f"[DEBUG-S404] Found keywords: {', '.join(keyword_matches)}")
                return True
            
            # Normalize content for signature comparison
            content = self._normalize_content(response.text)
            if self.debug:
                print(f"[DEBUG-S404] Normalized content: {len(content)} characters")
            
            # Check similarity with not found page signatures
            if self.debug:
                print(f"[DEBUG-S404] Checking similarity with {len(self.not_found_signatures)} 404 signatures")
            for i, signature in enumerate(self.not_found_signatures):
                similarity = self._calculate_similarity(content, signature)
                if self.debug:
                    print(f"[DEBUG-S404] Similarity with signature {i+1}: {similarity:.4f} (threshold: {self.threshold})")
                
                if similarity >= self.threshold:
                    # If very similar to 404 signature but has a distinctive title,
                    # it might be a real page and not a soft 404
                    if similarity > 0.98:
                        # Check page title
                        title_match = re.search(r'<title[^>]*>([^<]+)</title>', response.text)
                        if title_match:
                            title = title_match.group(1).lower()
                            # Check if title does NOT indicate an error page
                            if not any(term in title for term in ['not found', 'error', '404', 'not exist']):
                                # If title is descriptive and doesn't indicate error, probably a real page
                                if len(title) > 10 and 'example' not in title.lower():
                                    if self.debug:
                                        print(f"[DEBUG-S404] Not soft 404: high similarity but descriptive title: '{title}'")
                                    return False
                    
                    if self.debug:
                        print(f"[DEBUG-S404] Is soft 404: similarity {similarity:.4f} >= {self.threshold}")
                    return True
                
            if self.debug:
                print(f"[DEBUG-S404] Not soft 404: no match with signatures or keywords")
            return False
            
        except Exception as e:
            if self.debug:
                print(f"[DEBUG-S404] Error checking {url}: {str(e)}")
            return False
        
def main():
    parser = argparse.ArgumentParser(description='Soft 404 Detector for FuzzStorm')
    parser.add_argument('-u', '--url', required=True, help='Base URL to test')
    parser.add_argument('-f', '--file', help='File with list of URLs to check')
    parser.add_argument('-t', '--threshold', type=float, default=0.9, help='Similarity threshold (0.0-1.0)')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout for HTTP requests')
    parser.add_argument('--user-agent', help='Custom User-Agent')
    parser.add_argument('--proxy', help='Proxy for requests (e.g: http://127.0.0.1:8080)')
    parser.add_argument('-o', '--output', help='File to save results')
    parser.add_argument('--debug', action='store_true', help='Show debug messages')
    args = parser.parse_args()
    
    # Initialize detector
    detector = Soft404Detector(
        args.url,
        threshold=args.threshold,
        timeout=args.timeout,
        user_agent=args.user_agent,
        proxy=args.proxy,
        debug=args.debug
    )
    
    # List to store URLs
    urls_to_check = []
    
    # Read URLs from file
    if args.file:
        try:
            with open(args.file, 'r') as f:
                urls_to_check = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"Error reading file: {e}")
            sys.exit(1)
    else:
        print("ERROR: A file with URLs is required (-f)")
        sys.exit(1)
    
    # Filter only URLs with code 200
    print(f"[*] Checking {len(urls_to_check)} URLs to detect soft 404s...")
    
    # Results
    soft_404s = []
    real_200s = []
    
    # Process URLs
    for url in urls_to_check:
        is_soft_404 = detector.detect_soft_404(url)
        if is_soft_404:
            print(f"[SOFT 404] {url}")
            soft_404s.append(url)
        else:
            print(f"[REAL 200] {url}")
            real_200s.append(url)
    
    # Show summary
    print(f"\n[*] Summary:")
    print(f"    - URLs checked: {len(urls_to_check)}")
    print(f"    - Soft 404s detected: {len(soft_404s)}")
    print(f"    - Real 200s: {len(real_200s)}")
    
    # Save results if output file specified
    if args.output:
        try:
            with open(args.output, 'w') as f:
                f.write("# SOFT 404s\n")
                for url in soft_404s:
                    f.write(f"{url}\n")
                f.write("\n# REAL 200s\n")
                for url in real_200s:
                    f.write(f"{url}\n")
            print(f"[*] Results saved in {args.output}")
        except Exception as e:
            print(f"Error saving results: {e}")
    
if __name__ == "__main__":
    main() 