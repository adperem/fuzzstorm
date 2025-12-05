#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import argparse
import sys
import time
import re
import os
import json
import random
import string
import socket
import dns.resolver
import threading
import datetime
import csv
import signal
import concurrent.futures
import subprocess
import tempfile
import shutil
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm

# Import the soft 404 detector
try:
    from detect_soft_404 import Soft404Detector
    SOFT_404_DETECTOR_AVAILABLE = True
except ImportError:
    SOFT_404_DETECTOR_AVAILABLE = False


# Colors for the terminal
class Colors:
    RESET = "\033[0m"
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"

    # Background colors
    BG_BLACK = "\033[40m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN = "\033[46m"
    BG_WHITE = "\033[47m"

    @staticmethod
    def status_color(status_code):
        """Returns a color based on the HTTP status code"""
        if 200 <= status_code < 300:  # Success
            return Colors.GREEN
        elif 300 <= status_code < 400:  # Redirection
            return Colors.BLUE
        elif 400 <= status_code < 500:  # Client error
            return Colors.YELLOW
        elif 500 <= status_code < 600:  # Server error
            return Colors.RED
        else:
            return Colors.RESET

    @staticmethod
    def format_status(status_code):
        """Formats the HTTP status code with color"""
        color = Colors.status_color(status_code)
        return f"{color}[{status_code}]{Colors.RESET}"

    @staticmethod
    def format_error(message):
        """Formats an error message"""
        return f"{Colors.RED}[ERROR]{Colors.RESET} {message}"

    @staticmethod
    def format_info(message):
        """Formats an informational message"""
        return f"{Colors.BLUE}[*]{Colors.RESET} {message}"

    @staticmethod
    def format_success(message):
        """Formats a success message"""
        return f"{Colors.GREEN}[+]{Colors.RESET} {message}"

    @staticmethod
    def format_warning(message):
        """Formats a warning message"""
        return f"{Colors.YELLOW}[!]{Colors.RESET} {message}"

    @staticmethod
    def format_path(path):
        """Formats a path with color"""
        return f"{Colors.CYAN}{path}{Colors.RESET}"

    @staticmethod
    def format_size(size):
        """Formats a size with color"""
        return f"{Colors.MAGENTA}{size}{Colors.RESET}"

    @staticmethod
    def format_domain(domain):
        """Formats a domain with color"""
        return f"{Colors.BOLD}{Colors.GREEN}{domain}{Colors.RESET}"

    @staticmethod
    def format_ip(ip):
        """Formats an IP with color"""
        return f"{Colors.YELLOW}{ip}{Colors.RESET}"


# Global variable and event to control scan interruption
scan_interrupted = False
scan_interrupt_event = threading.Event()


def reset_scan_interruption():
    """Resets interruption flags for a new scan phase."""
    global scan_interrupted
    scan_interrupted = False
    scan_interrupt_event.clear()


# Handler for SIGINT signal (Ctrl+C)
def handle_keyboard_interrupt(signum, frame):
    global scan_interrupted
    scan_interrupted = True
    scan_interrupt_event.set()
    print("\n[!] Interruption detected. Stopping current scan...")
    # Do not call sys.exit() to allow the program to continue


# Default extensions for scanning
DEFAULT_EXTENSIONS = [".php", ".html", ".txt", ".js", ".json", ".xml", ".bak", ".zip", ".tar", ".gz", ".conf", ".log",
                      ".old", ".inc", ".swp"]

# HTTP methods to test when receiving 405 Method Not Allowed
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

# Test data for methods requiring a body (POST, PUT, PATCH)
TEST_DATA = {
    "generic": {
        "test": "test",
        "id": "1",
        "name": "test",
        "value": "test123",
        "email": "test@example.com",
        "password": "password123"
    },
    "json": {
        "username": "admin",
        "password": "admin",
        "email": "admin@example.com",
        "id": 1,
        "action": "login",
        "token": "12345abcde"
    },
    "form": {
        "username": "admin",
        "password": "admin",
        "submit": "Login",
        "token": "csrf_token_value"
    }
}

# Common security headers to check
SECURITY_HEADERS = {
    "Strict-Transport-Security": "Missing HSTS header that enforces HTTPS connections",
    "Content-Security-Policy": "Missing CSP header that protects against XSS attacks",
    "X-Content-Type-Options": "Missing X-Content-Type-Options: nosniff header that prevents MIME-sniffing attacks",
    "X-Frame-Options": "Missing X-Frame-Options header that protects against clickjacking",
    "X-XSS-Protection": "Missing X-XSS-Protection header that helps prevent XSS in older browsers",
    "Referrer-Policy": "Missing Referrer-Policy header that controls information sent in the Referer header",
    "Permissions-Policy": "Missing Permissions-Policy header (formerly Feature-Policy) to control browser features"
}

# Common vulnerability patterns to search for in page content
VULNERABILITY_PATTERNS = {
    "error_sql": (r"(SQL syntax.*?|Warning.*?SQL|ORA-[0-9]+|MySQL Error|MariaDB Error)",
                  "Possible SQL Injection error"),
    "error_php": (r"(Warning.*?PHP|Fatal error.*?PHP|Parse error.*?PHP|Notice.*?PHP)", "Exposed PHP error"),
    "error_asp": (
        r"(Microsoft OLE DB Provider for SQL Server error|ADODB.Command|Microsoft VBScript runtime error|Microsoft VBScript compilation error)",
        "Exposed ASP error"),
    "internal_paths": (r"(\/var\/www\/|C:\\inetpub\\|C:\\xampp\\|\/usr\/local\/|\/home\/\w+\/public_html\/)",
                       "Exposure of internal server paths"),
    "api_keys": (r"(api_key|apikey|client_secret|auth_token|access_token)[\s]*[=:][\s]*['\"]([\w\-]+)['\"]",
                 "Possible API key exposure"),
    "jwt_token": (r"(eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)", "Possible JWT token exposure"),
    "aws_keys": (r"(AKIA[A-Z0-9]{16})", "Possible AWS access key exposure"),
    "dir_listing": (r"(?is)<title>Index of /|<h1>Index of /", "Directory listing appears to be enabled"),
    "stack_trace_java": (r"Exception in thread \\\".*?\\\" .*?\.java:\\d+", "Java stack trace exposed"),
    "stack_trace_python": (r"Traceback \(most recent call last\):", "Python traceback exposed"),
    "debug_tokens": (r"(?i)werkzeug debugger|django debug|X-Debug-Token", "Debug information disclosed"),
    "config_leak": (r"(DB_PASSWORD|DATABASE_URL|SECRET_KEY)[\s]*[=:][\s]*['\"]?([^'\"\s]+)", "Potential configuration secret exposure"),
}

class ProgressMonitor:
    """Monitors progress and request rate"""

    def __init__(self, total, desc="Progress", unit="req", use_colors=True):
        self.total = total
        self.desc = desc
        self.unit = unit
        self.completed = 0
        self.start_time = time.time()
        self.last_update_time = self.start_time
        self.requests_since_last_update = 0
        self.requests_per_second = 0
        self.lock = threading.Lock()
        self.use_colors = use_colors
        self.interrupted = False

        # Initialize the progress bar
        self.progress_bar = tqdm(
            total=total,
            desc=desc,
            unit=unit,
            bar_format="{desc}: {percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}{postfix}]"
        )

        # Start the stats update thread
        self.running = True
        self.stats_thread = threading.Thread(target=self._update_stats)
        self.stats_thread.daemon = True
        self.stats_thread.start()

    def update(self, n=1):
        """Updates the progress"""
        with self.lock:
            self.completed += n
            self.requests_since_last_update += n
            self.progress_bar.update(n)

    def _update_stats(self):
        """Periodically updates the statistics"""
        while self.running:
            time.sleep(1)  # Update every second
            now = time.time()
            elapsed = now - self.last_update_time

            with self.lock:
                if elapsed > 0:
                    self.requests_per_second = self.requests_since_last_update / elapsed
                    self.progress_bar.set_postfix(rps=f"{self.requests_per_second:.1f} req/s")
                    self.requests_since_last_update = 0
                    self.last_update_time = now

    def close(self):
        """Closes the progress bar and stops the stats thread"""
        self.running = False
        if self.stats_thread.is_alive():
            self.stats_thread.join(1)

        elapsed = time.time() - self.start_time
        avg_rps = self.completed / elapsed if elapsed > 0 else 0

        self.progress_bar.set_postfix(rps=f"{avg_rps:.1f} req/s (average)")
        self.progress_bar.close()

        if self.use_colors:
            self.print(Colors.format_info(f"Completed in {elapsed:.2f} seconds, {avg_rps:.1f} req/s (average)"))
        else:
            self.print(f"[*] Completed in {elapsed:.2f} seconds, {avg_rps:.1f} req/s (average)")

    def print(self, message):
        """Prints a message without interrupting the progress bar"""
        tqdm.write(message)

    def interrupt(self):
        """Marks the monitor as interrupted"""
        self.interrupted = True
        self.close()


class SecurityAnalyzer:
    """Analyzes responses for security issues"""

    def __init__(self, use_colors=True):
        self.use_colors = use_colors
        self.findings = {}
        self.compiled_patterns = {
            vuln_id: (re.compile(pattern), description)
            for vuln_id, (pattern, description) in VULNERABILITY_PATTERNS.items()
        }

    def add_techackz_results(self, url, technologies, vulnerabilities, raw_output):
        """Stores results returned by Techackz integration.

        Args:
            url (str): Target URL analyzed.
            technologies (list): Normalized list of detected technologies.
            vulnerabilities (list): Normalized list of detected vulnerabilities.
            raw_output (dict): Raw JSON output from Techackz for reference.
        """
        self.findings.setdefault(url, {})
        self.findings[url]["techackz"] = {
            "technologies": technologies or [],
            "vulnerabilities": vulnerabilities or [],
            "raw_output": raw_output or {},
        }

    def check_security_headers(self, url, headers):
        """Checks for missing security headers"""
        missing_headers = []

        for header, description in SECURITY_HEADERS.items():
            if header not in headers:
                missing_headers.append((header, description))

        if missing_headers:
            self.findings.setdefault(url, {})
            self.findings[url]["missing_security_headers"] = missing_headers

        return missing_headers

    def scan_for_vulnerabilities(self, url, content, status_code, headers=None):
        """Searches for patterns that may indicate vulnerabilities"""
        findings = []

        # Convert content to string if it is bytes
        if isinstance(content, bytes):
            try:
                content_str = content.decode('utf-8')
            except UnicodeDecodeError:
                # If it cannot be decoded as UTF-8, try another encoding or ignore
                try:
                    content_str = content.decode('latin-1')
                except:
                    return findings
        else:
            content_str = str(content)

        # Search for vulnerability patterns
        for vuln_id, (pattern, description) in self.compiled_patterns.items():
            matches = pattern.findall(content_str)
            if matches:
                finding = {
                    "type": vuln_id,
                    "description": description,
                    "matches": matches[:5]  # Limit to 5 matches to avoid overload
                }
                findings.append(finding)

        # Check exposed version identifiers in response headers
        if headers:
            header_findings = []
            for header_name in ("Server", "X-Powered-By"):
                header_value = headers.get(header_name)
                if header_value and any(char.isdigit() for char in header_value):
                    header_findings.append({
                        "type": "server_version",
                        "description": f"{header_name} header exposes software version information",
                        "matches": [header_value]
                    })
            findings.extend(header_findings)

        # Check 200 OK responses with small size (may indicate API endpoints)
        if status_code == 200 and len(content) < 100:
            findings.append({
                "type": "small_response",
                "description": "200 OK response with small size, possible API endpoint",
                "matches": [f"Size: {len(content)} bytes"]
            })

        if findings:
            self.findings.setdefault(url, {})
            self.findings[url]["vulnerabilities"] = findings

        return findings

    def generate_report(self):
        """Generates a report with all security findings"""
        return self.findings

class FuzzStorm:
    def __init__(self, target_url, wordlist, extensions=None, threads=10, delay=0, test_methods=True,
                 proxy=None, use_colors=True, security_analysis=False,
                 detect_soft_404=True, soft_404_threshold=0.9, debug=False):
        self.target_url = target_url if target_url.endswith('/') else target_url + '/'
        self.wordlist = wordlist
        self.extensions = extensions if extensions else DEFAULT_EXTENSIONS
        self.threads = threads
        self.delay = delay
        self.test_methods = test_methods
        self.proxy = proxy
        self.use_colors = use_colors
        self.security_analysis = security_analysis
        self.detect_soft_404 = detect_soft_404 and SOFT_404_DETECTOR_AVAILABLE
        self.soft_404_threshold = soft_404_threshold
        self.debug = debug
        self.soft_404_detector = None
        self._soft_404_cache = {}
        
        # Show banner at startup
        self.show_banner()
        
        # Initialize other attributes
        self.discovered_urls = set()
        self.discovered_subdomains = set()
        self.method_success = {}  # To store successful methods per URL
        self.responses = {}  # To store response information
        self.content_scan_done = False  # To track if content scanning has been performed
        self.soft_404s = set()  # URLs identified as soft 404s
        self.real_200s = set()  # URLs identified as real 200s

        # Initialize counters for 403 codes
        self.forbidden_count = 0
        self.forbidden_urls = []
        self.last_forbidden_report_time = time.time()

        # Initialize counters for 404 codes
        self.not_found_count = 0
        self.not_found_urls = []
        self.last_not_found_report_time = time.time()

        # Initialize the security analyzer if enabled
        if security_analysis:
            self.security_analyzer = SecurityAnalyzer(use_colors=use_colors)

        # For the soft 404 detector, initialize it on demand
        # when the first 200 response is found
        # This avoids slowing down startup with 404 signature requests
        #if self.detect_soft_404:
        #    print(f"[*] Soft 404 detection enabled (threshold: {self.soft_404_threshold})")

        if self.debug:
            print(f"[DEBUG] Debug mode enabled")

        # Set up the session with the proxy if specified
        self.session = requests.Session()
        self.configure_session()

        self.current_progress_monitor = None

    def configure_session(self):
        """Configures the HTTP session with necessary parameters"""
        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': 'FuzzStorm/1.0',
            'Accept': '*/*'
        }

        if self.proxy:
            self.session.proxies = {
                'http': self.proxy,
                'https': self.proxy
            }
            print(f"[*] Using proxy: {self.proxy}")

    def _ensure_techackz_repo(self):
        """Clones Techackz locally if it is not already available."""
        repo_url = "https://github.com/gotr00t0day/Techackz.git"
        base_dir = os.path.join(tempfile.gettempdir(), "techackz")

        if os.path.isdir(os.path.join(base_dir, ".git")):
            return base_dir

        if os.path.exists(base_dir):
            try:
                shutil.rmtree(base_dir)
            except OSError:
                pass

        try:
            subprocess.run([
                "git", "clone", "--depth", "1", repo_url, base_dir
            ], check=True, capture_output=True, text=True)
        except FileNotFoundError:
            print(Colors.format_error("Git is not available to clone Techackz. Skipping Techackz integration."))
            return None
        except subprocess.CalledProcessError as exc:
            error_msg = exc.stderr.strip() if exc.stderr else str(exc)
            print(Colors.format_error(f"Unable to clone Techackz: {error_msg}"))
            return None

        return base_dir

    def _extract_techackz_summary(self, raw_results):
        """Builds a small summary from Techackz JSON results."""
        technologies = []
        vulnerabilities = []

        def _extend_from_candidate(candidate, container):
            if isinstance(candidate, list):
                container.extend(candidate)

        if isinstance(raw_results, dict):
            _extend_from_candidate(raw_results.get("technologies"), technologies)
            _extend_from_candidate(raw_results.get("detected_technologies"), technologies)
            _extend_from_candidate(raw_results.get("vulnerabilities"), vulnerabilities)
            _extend_from_candidate(raw_results.get("nuclei_findings"), vulnerabilities)

            for nested_key in ("results", "targets", "scan_results"):
                nested = raw_results.get(nested_key)
                if isinstance(nested, dict):
                    for value in nested.values():
                        if isinstance(value, dict):
                            _extend_from_candidate(value.get("technologies"), technologies)
                            _extend_from_candidate(value.get("detected_technologies"), technologies)
                            _extend_from_candidate(value.get("vulnerabilities"), vulnerabilities)
                            _extend_from_candidate(value.get("nuclei_findings"), vulnerabilities)

        return technologies, vulnerabilities

    def run_techackz_analysis(self):
        """Runs Techackz to enumerate technologies and vulnerabilities."""
        repo_dir = self._ensure_techackz_repo()
        if not repo_dir:
            return

        print(Colors.format_info("Running Techackz technology and vulnerability analysis..."))

        env = os.environ.copy()
        if self.proxy:
            env.update({
                "HTTP_PROXY": self.proxy,
                "HTTPS_PROXY": self.proxy,
                "ALL_PROXY": self.proxy,
            })

        output_path = None
        try:
            with tempfile.NamedTemporaryFile(prefix="techackz_", suffix=".json", delete=False) as tmp_output:
                output_path = tmp_output.name

            command = [
                sys.executable,
                os.path.join(repo_dir, "techackz.py"),
                "-u", self.target_url,
                "-o", output_path,
                "--show-all-detections",
            ]

            if self.proxy:
                command.append("--ignore-ssl")

            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                env=env
            )

            if result.returncode != 0:
                print(Colors.format_warning("Techackz returned a non-zero exit code; skipping integration."))
                if result.stdout:
                    print(result.stdout.strip())
                if result.stderr:
                    print(result.stderr.strip())
                return

            if not os.path.isfile(output_path):
                print(Colors.format_warning("Techackz did not produce an output file."))
                return

            with open(output_path, "r") as tech_file:
                try:
                    raw_results = json.load(tech_file)
                except json.JSONDecodeError:
                    print(Colors.format_warning("Unable to parse Techackz JSON output."))
                    return

            technologies, vulnerabilities = self._extract_techackz_summary(raw_results)
            if hasattr(self, 'security_analyzer'):
                self.security_analyzer.add_techackz_results(
                    self.target_url, technologies, vulnerabilities, raw_results)
                print(Colors.format_success("Techackz results added to security analysis."))
        finally:
            if output_path:
                try:
                    os.remove(output_path)
                except Exception:
                    pass

    def clean_wordlist(self, raw_wordlist):
        """Cleans the wordlist: removes empty lines and comments (starting with #)"""
        clean_entries = []
        ignored_comments = 0

        for i, entry in enumerate(raw_wordlist):
            # Remove leading and trailing whitespace
            entry = entry.strip()

            # Skip empty lines or comments (starting with #)
            if not entry:
                continue

            if entry.startswith('#'):
                ignored_comments += 1
                continue

            # Add the entry as is
            clean_entries.append(entry)

        # Report ignored comments
        if ignored_comments > 0:
            print(f"[*] Ignored {ignored_comments} comment lines (starting with #)")

        return clean_entries

    def load_wordlist(self):
        """Loads the wordlist, trying different encodings if necessary"""
        encodings = ['utf-8', 'latin-1', 'iso-8859-1', 'cp1252']

        for encoding in encodings:
            try:
                with open(self.wordlist, 'r', encoding=encoding) as f:
                    raw_entries = [line.strip() for line in f if line.strip()]

                # Validate and clean the wordlist
                print(f"[*] Loading and cleaning wordlist: {self.wordlist} (encoding: {encoding})")
                cleaned_entries = self.clean_wordlist(raw_entries)

                print(f"[*] Wordlist loaded: {len(cleaned_entries)} valid entries out of {len(raw_entries)} total")

                return cleaned_entries
            except UnicodeDecodeError:
                # If encoding fails, try the next one
                continue
            except Exception as e:
                print(f"Error loading wordlist: {e}")
                sys.exit(1)

        # If we reach here, no encoding worked
        print(
            f"[-] Error: Could not load wordlist with any encoding. Try converting the file to UTF-8.")
        sys.exit(1)

    def generate_random_data(self, length=8):
        """Generates random data for form and API testing"""
        return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

    def prepare_test_data(self, url):
        """Prepares test data for different formats"""
        # Generate random data for some keys
        random_str = self.generate_random_data()

        # Create copies of test data with random values
        form_data = TEST_DATA["form"].copy()
        form_data["username"] = f"user_{random_str}"
        form_data["password"] = f"pass_{random_str}"

        json_data = TEST_DATA["json"].copy()
        json_data["username"] = f"api_user_{random_str}"
        json_data["password"] = f"api_pass_{random_str}"

        # Create specific data based on the URL
        path = urlparse(url).path
        filename = os.path.basename(path)
        name, ext = os.path.splitext(filename)

        if name:
            form_data["id"] = name
            json_data["resource"] = name

        return {
            "form": form_data,
            "json": json_data,
            "empty": {},
            "text": f"test_data={random_str}&id=1&action=test"
        }

    def _ensure_soft_404_detector(self):
        """Create the soft 404 detector once and reuse it across requests."""
        if not (self.detect_soft_404 and SOFT_404_DETECTOR_AVAILABLE):
            return None

        if self.soft_404_detector:
            return self.soft_404_detector

        self.soft_404_detector = Soft404Detector(
            target_url=self.target_url,
            threshold=self.soft_404_threshold,
            proxy=self.proxy,
            user_agent=self.session.headers.get('User-Agent'),
            debug=self.debug
        )
        return self.soft_404_detector

    def _is_soft_404(self, url):
        """Check whether a URL likely represents a soft 404, caching results for speed."""
        if not (self.detect_soft_404 and SOFT_404_DETECTOR_AVAILABLE):
            return False

        if url in self._soft_404_cache:
            return self._soft_404_cache[url]

        detector = self._ensure_soft_404_detector()
        if not detector:
            self._soft_404_cache[url] = False
            return False

        is_soft_404 = False
        try:
            is_soft_404 = detector.detect_soft_404(url)
        finally:
            self._soft_404_cache[url] = is_soft_404

        if is_soft_404:
            self.soft_404s.add(url)
        else:
            self.real_200s.add(url)

        return is_soft_404

    def try_different_methods(self, url, progress_monitor=None):
        """Tries different HTTP methods when a 405 Method Not Allowed is encountered"""
        successful_methods = []
        test_data = self.prepare_test_data(url)

        # Format the message
        if self.use_colors:
            path_str = Colors.format_path(url)
            info_msg = Colors.format_info(f"Testing alternative methods for: {path_str}")
        else:
            info_msg = f"\n[*] Testing alternative methods for: {url}"

        # Use the progress monitor's print method to avoid overlap
        if progress_monitor:
            progress_monitor.print(info_msg)
        else:
            print(info_msg)

        # Create a table for the results
        header = "+--------+----------------+--------+----------------+"
        if progress_monitor:
            progress_monitor.print(header)
            progress_monitor.print("| Method | Data Type      | Status | Size           |")
            progress_monitor.print(header)
        else:
            print(header)
            print("| Method | Data Type      | Status | Size           |")
            print(header)

        for method in HTTP_METHODS:
            if method == "GET":  # Already tested earlier
                continue

            try:
                if method in ["POST", "PUT", "PATCH"]:
                    # Test with different data types
                    # 1. application/json
                    headers = {'Content-Type': 'application/json'}
                    response = self.session.request(
                        method=method,
                        url=url,
                        json=test_data["json"],
                        headers=headers,
                        timeout=10,
                        allow_redirects=False
                    )
                    status = response.status_code
                    content_length = len(response.content)

                    if status not in [404, 405, 501]:
                        successful_methods.append((method, status, content_length, "application/json"))

                        # Format the message as a table
                        status_str = str(status)
                        if self.use_colors:
                            status_str = Colors.status_color(status) + status_str + Colors.RESET

                        row = f"| {method.ljust(6)} | {'JSON'.ljust(14)} | {status_str.ljust(6)} | {str(content_length).ljust(14)} |"
                        if progress_monitor:
                            progress_monitor.print(row)
                        else:
                            print(row)

                    # 2. application/x-www-form-urlencoded
                    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
                    response = self.session.request(
                        method=method,
                        url=url,
                        data=test_data["form"],
                        headers=headers,
                        timeout=10,
                        allow_redirects=False
                    )
                    status = response.status_code
                    content_length = len(response.content)

                    if status not in [404, 405, 501]:
                        successful_methods.append((method, status, content_length, "form-urlencoded"))

                        # Format the message as a table
                        status_str = str(status)
                        if self.use_colors:
                            status_str = Colors.status_color(status) + status_str + Colors.RESET

                        row = f"| {method.ljust(6)} | {'Form-URL'.ljust(14)} | {status_str.ljust(6)} | {str(content_length).ljust(14)} |"
                        if progress_monitor:
                            progress_monitor.print(row)
                        else:
                            print(row)

                else:
                    # For other methods like OPTIONS, HEAD, etc.
                    response = self.session.request(
                        method=method,
                        url=url,
                        timeout=10,
                        allow_redirects=False
                    )
                    status = response.status_code
                    content_length = len(response.content)

                    if status not in [404, 405, 501]:
                        successful_methods.append((method, status, content_length, ""))

                        # Format the message as a table
                        status_str = str(status)
                        if self.use_colors:
                            status_str = Colors.status_color(status) + status_str + Colors.RESET

                        row = f"| {method.ljust(6)} | {'-'.ljust(14)} | {status_str.ljust(6)} | {str(content_length).ljust(14)} |"
                        if progress_monitor:
                            progress_monitor.print(row)
                        else:
                            print(row)

                # Pause between requests if a delay was specified
                if self.delay > 0:
                    time.sleep(self.delay)

            except requests.RequestException:
                continue

        # Close the table
        if progress_monitor:
            progress_monitor.print(header)
        else:
            print(header)

        if successful_methods:
            self.method_success[url] = successful_methods
            return True

        # Format the message
        if self.use_colors:
            warning_msg = f"  {Colors.YELLOW}[-]{Colors.RESET} No alternative methods found for: {Colors.format_path(url)}"
        else:
            warning_msg = f"  [-] No alternative methods found for: {url}"

        if progress_monitor:
            progress_monitor.print(warning_msg)
        else:
            print(warning_msg)

        return False

    def make_request(self, url, progress_monitor=None):
        """Makes an HTTP request and updates the progress bar if it exists"""
        if self.debug:
            print(f"[DEBUG] Sending GET request to: {url}")

        # Configure timeout and retries
        request_timeout = 10
        max_retries = 1
        last_exception = None

        for retry in range(max_retries):
            if scan_interrupt_event.is_set():
                return url, None
            try:
                # Measure response time
                start_time = time.time()
                response = self.session.get(url, allow_redirects=False, timeout=request_timeout)
                response_time = (time.time() - start_time) * 1000  # Convert to milliseconds

                if self.debug:
                    print(
                        f"[DEBUG] Response received: {response.status_code}, time: {response_time:.2f}ms, size: {len(response.content)} bytes")

                status = response.status_code

                # Store response information for later analysis
                content_length = len(response.content)
                self.responses[url] = {
                    "status": status,
                    "content_length": content_length,
                    "headers": dict(response.headers),
                    "content": response.content,
                    "response_time": response_time  # Add response time
                }

                # Perform security analysis if enabled
                if self.security_analysis and hasattr(self, 'security_analyzer'):
                    # Check security headers
                    self.security_analyzer.check_security_headers(url, response.headers)
                    # Scan content for vulnerabilities
                    self.security_analyzer.scan_for_vulnerabilities(
                        url, response.content, status, headers=response.headers)

                # Add to discovered URLs (regardless of status code)
                # This ensures all URLs that receive a response are considered discovered
                self.discovered_urls.add(url)

                # Display result in real-time (except 404)
                if status != 404:
                    # Special handling for 403 Forbidden to avoid flooding output
                    if status == 403:
                        # Update 403 counters (already initialized in __init__)
                        self.forbidden_count += 1
                        self.forbidden_urls.append(url)

                        # Display 403 summary every 10 results or every 5 seconds
                        current_time = time.time()
                        if self.forbidden_count % 10 == 0 or (current_time - self.last_forbidden_report_time) > 5:
                            if self.use_colors:
                                status_str = Colors.format_status(403)
                                msg = f"{status_str} Received {self.forbidden_count} 403 Forbidden responses (last: {url})"
                            else:
                                msg = f"[403] Received {self.forbidden_count} 403 Forbidden responses (last: {url})"

                            if progress_monitor:
                                progress_monitor.print(msg)
                            else:
                                print(msg)

                            self.last_forbidden_report_time = current_time
                    elif status == 200:
                        # Check if it's a soft 404 or a true 200 (cached to avoid repeated work)
                        try:
                            is_soft_404 = self._is_soft_404(url)
                        except Exception as e:
                            is_soft_404 = False
                            if self.debug:
                                print(f"[DEBUG] Error detecting soft 404: {e}")

                        if is_soft_404:
                            if self.use_colors:
                                status_str = Colors.YELLOW + "[SOFT 404]" + Colors.RESET
                                path_str = Colors.format_path(url)
                                size_str = Colors.format_size(f"{content_length} bytes")
                                msg = f"{status_str} {path_str} - {size_str}"
                            else:
                                msg = f"[SOFT 404] {url} - {content_length} bytes"
                        else:
                            if self.use_colors:
                                status_str = Colors.format_status(200)
                                path_str = Colors.format_path(url)
                                size_str = Colors.format_size(f"{content_length} bytes")
                                msg = f"{status_str} {path_str} - {size_str}"
                            else:
                                msg = f"[200] {url} - {content_length} bytes"

                        if progress_monitor:
                            progress_monitor.print(msg)
                        else:
                            print(msg)
                else:
                    # Special handling for 404 Not Found to avoid flooding output
                    self.not_found_count += 1
                    self.not_found_urls.append(url)

                    # Display 404 summary every 20 results or every 5 seconds
                    current_time = time.time()
                    if self.not_found_count % 20 == 0 or (current_time - self.last_not_found_report_time) > 5:
                        if self.use_colors:
                            status_str = Colors.format_status(404)
                            msg = f"{status_str} Received {self.not_found_count} 404 Not Found responses (last: {url})"
                        else:
                            msg = f"[404] Received {self.not_found_count} 404 Not Found responses (last: {url})"

                        if progress_monitor:
                            progress_monitor.print(msg)
                        else:
                            print(msg)

                        self.last_not_found_report_time = current_time

                    # Update progress if there is a monitor
                    if progress_monitor:
                        progress_monitor.update(1)

                    return url, response

            except requests.Timeout as e:
                # Store the exception
                last_exception = e

                # If retries remain, continue
                if retry < max_retries - 1:
                    retry_wait = 2 * (retry + 1)  # Exponential wait
                    if self.debug:
                        print(
                            f"[DEBUG] Timeout connecting to {url}, retrying in {retry_wait}s ({max_retries - retry - 1} attempts remaining)")
                    time.sleep(retry_wait)
                    continue

            except requests.RequestException as e:
                # Store the exception and do not retry other errors besides timeout
                last_exception = e
                break

            # If we reach here, retries were exhausted or a non-retryable exception occurred
            if last_exception:
                retry_info = f" (after {max_retries} attempts)" if max_retries > 1 else ""

                if self.use_colors:
                    error_msg = Colors.format_error(f"{url} - {str(last_exception)}{retry_info}")
                else:
                    error_msg = f"[ERROR] | {url} - {str(last_exception)}{retry_info}"

                if progress_monitor:
                    progress_monitor.print(error_msg)
                else:
                    print(error_msg)

                # Update progress even if there is an error
                if progress_monitor:
                    progress_monitor.update(1)

        return url, None

    def scan_url(self, path, progress_monitor=None):
        """Scans a URL and updates the progress"""
        if self.debug:
            print(f"[DEBUG] Scanning path: {path}")

        if scan_interrupt_event.is_set():
            return None

        if self.delay > 0:
            if self.debug:
                print(f"[DEBUG] Applying delay of {self.delay} seconds")
            time.sleep(self.delay)

        url = urljoin(self.target_url, path)
        if self.debug:
            print(f"[DEBUG] Full URL: {url}")

        url, response = self.make_request(url, progress_monitor)
        return url

    def show_forbidden_summary(self):
        """Displays a summary of URLs with 403 Forbidden status code"""
        if self.forbidden_count > 0:
            print(f"\n[!] Summary of 403 Forbidden responses:")
            print(f"    Received {self.forbidden_count} responses with 403 Forbidden status code")

            # Create table to display results
            print("\n    +------------------------------------------------------------------------------+")
            print("    | URLs with 403 Forbidden status code                                          |")
            print("    +------------------------------------------------------------------------------+")

            # If there are too many, show only some as examples
            max_display = 10
            urls_to_show = self.forbidden_urls[:max_display]

            for url in urls_to_show:
                # Limit URL length to fit in the table
                display_url = url
                if len(url) > 74:
                    display_url = url[:71] + "..."

                if self.use_colors:
                    path_str = Colors.format_path(display_url)
                    print(f"    | {path_str}" + " " * (76 - len(display_url)) + "|")
                else:
                    print(f"    | {display_url}" + " " * (76 - len(display_url)) + "|")

            if len(self.forbidden_urls) > max_display:
                remaining = len(self.forbidden_urls) - max_display
                print("    |" + "-" * 76 + "|")
                print(
                    f"    | ... and {remaining} more URLs (see full report)" + " " * (42 - len(str(remaining))) + "|")

            print("    +------------------------------------------------------------------------------+")

    def show_not_found_summary(self):
        """Displays a summary of URLs with 404 Not Found status code"""
        if self.not_found_count > 0:
            print(f"\n[!] Summary of 404 Not Found responses:")
            print(f"    Received {self.not_found_count} responses with 404 Not Found status code")

            # Create table to display results
            print("\n    +------------------------------------------------------------------------------+")
            print("    | URLs with 404 Not Found status code                                          |")
            print("    +------------------------------------------------------------------------------+")

            # If there are too many, show only some as examples
            max_display = 10
            urls_to_show = self.not_found_urls[:max_display]

            for url in urls_to_show:
                # Limit URL length to fit in the table
                display_url = url
                if len(url) > 74:
                    display_url = url[:71] + "..."

                if self.use_colors:
                    path_str = Colors.format_path(display_url)
                    print(f"    | {path_str}" + " " * (76 - len(display_url)) + "|")
                else:
                    print(f"    | {display_url}" + " " * (76 - len(display_url)) + "|")

            if len(self.not_found_urls) > max_display:
                remaining = len(self.not_found_urls) - max_display
                print("    |" + "-" * 76 + "|")
                print(
                    f"    | ... and {remaining} more URLs (see full report)" + " " * (42 - len(str(remaining))) + "|")

            print("    +------------------------------------------------------------------------------+")

    def normal_scan(self):
        """Normal scan: searches paths directly from the wordlist"""
        reset_scan_interruption()

        print("\n" + "="*80)
        if self.use_colors:
            print(f"{Colors.BOLD}{Colors.CYAN}[*] STARTING NORMAL SCAN{Colors.RESET}")
            print(f"{Colors.CYAN}[*] Threads: {Colors.BOLD}{self.threads}{Colors.RESET}")
        else:
            print("[*] STARTING NORMAL SCAN")
            print(f"[*] Threads: {self.threads}")
        print("="*80 + "\n")

        try:
            paths = self.load_wordlist()
            total_paths = len(paths)

            if self.use_colors:
                print(f"{Colors.YELLOW}[*] Scanning {Colors.BOLD}{total_paths}{Colors.RESET}{Colors.YELLOW} paths...{Colors.RESET}")
            else:
                print(f"[*] Scanning {total_paths} paths...")

            # Create progress monitor
            progress = ProgressMonitor(total=total_paths, desc="Normal Scan", unit="path")
            self.current_progress_monitor = progress

            # Wrapper function to update progress
            def scan_with_progress(path):
                global scan_interrupted
                if scan_interrupted:
                    return None
                return self.scan_url(path, progress)

            executor = ThreadPoolExecutor(max_workers=self.threads)
            try:
                futures = [executor.submit(scan_with_progress, path) for path in paths]

                for future in futures:
                    if scan_interrupted:
                        break

                    try:
                        future.result(timeout=0.1)
                    except concurrent.futures.TimeoutError:
                        continue
            finally:
                executor.shutdown(
                    wait=not scan_interrupted,
                    cancel_futures=scan_interrupted,
                )

            # Close the progress bar
            if scan_interrupted:
                progress.interrupt()
                print("\n[!] Normal scan interrupted by the user.")
            else:
                progress.close()
                found_count = len([url for url in self.discovered_urls if url.startswith(self.target_url)])
                print(f"\n[+] Normal scan completed. Found {found_count} resources.")

                # Display 403 summary if any
                self.show_forbidden_summary()

                # Display 404 summary if any
                self.show_not_found_summary()

        except Exception as e:
            print(f"\n[-] Error during normal scan: {e}")

        finally:
            self.current_progress_monitor = None
            return not scan_interrupted

    def recursive_scan(self, max_depth=6):
        """
        Enhanced hierarchical recursive scan that explores subdirectories at each level.
        This method will find nested paths like /recursive/level1/level2/level3 by exploring
        each discovered directory at every depth level.
        """
        reset_scan_interruption()

        print("\n" + "="*80)
        if self.use_colors:
            print(f"{Colors.BOLD}{Colors.MAGENTA}[*] STARTING RECURSIVE SCAN{Colors.RESET}")
            print(f"{Colors.MAGENTA}[*] Maximum depth: {Colors.BOLD}{max_depth}{Colors.RESET}")
            print(f"{Colors.MAGENTA}[*] Threads: {Colors.BOLD}{self.threads}{Colors.RESET}")
        else:
            print("[*] STARTING RECURSIVE SCAN")
            print(f"[*] Maximum depth: {max_depth}")
            print(f"[*] Threads: {self.threads}")
        print("="*80 + "\n")

        try:
            paths = self.load_wordlist()
            if not paths:
                print("[-] Wordlist is empty.")
                return True

            # Success codes to consider for further exploration
            success_codes = [200, 201, 202, 204, 301, 302, 307, 308]

            # Initialize directories to explore with successful URLs from previous scans
            discovered_dirs = set()

            # Find successful URLs from previous scans
            initial_dirs = set()

            # Start with the base URL as a fallback
            initial_dirs.add(self.target_url.rstrip('/') + '/')

            # Add URLs with successful status codes from previous scans
            for url, info in self.responses.items():
                if info.get("status") in success_codes:
                    # Ensure URL ends with a slash for directory exploration
                    if not url.endswith('/'):
                        url = url + '/'
                    initial_dirs.add(url)
                    discovered_dirs.add(url)

            if self.debug:
                print(
                    f"[DEBUG] Starting recursion with {len(initial_dirs)} base directories from previous scan results")
                for i, dir in enumerate(initial_dirs):
                    print(f"[DEBUG] Base dir {i + 1}: {dir}")

            current_level_dirs = initial_dirs
            current_depth = 0

            while current_depth < max_depth and current_level_dirs and not scan_interrupted:
                next_level_dirs = set()
                all_urls_to_check = []

                print(f"[*] Depth {current_depth + 1}: exploring {len(current_level_dirs)} directories")

                # Print the directories being explored to help troubleshoot
                print(f"[*] Exploring: {', '.join(list(current_level_dirs)[:3])}" +
                      (f" and {len(current_level_dirs) - 3} more..." if len(current_level_dirs) > 3 else ""))

                if self.debug:
                    print("[DEBUG] Current level directories to explore:")
                    for i, base_dir in enumerate(current_level_dirs):
                        print(f"[DEBUG] {i + 1}. {base_dir}")

                # Build URLs to check using current level directories as base
                for base_dir in current_level_dirs:
                    if self.debug:
                        print(f"[DEBUG] Building URLs from base directory: {base_dir}")

                    # Ensure base_dir ends with '/'
                    base_dir = base_dir if base_dir.endswith('/') else base_dir + '/'

                    for path in paths:
                        # Create the full URL by joining base_dir and the current path
                        # Add trailing slash to indicate directory for exploration
                        full_url = urljoin(base_dir, path)
                        all_urls_to_check.append(full_url)
                        if self.debug:
                            print(f"[DEBUG] Created URL: {full_url}")

                if not all_urls_to_check:
                    print("[*] No more URLs to check at this depth.")
                    break

                print(f"[*] Depth {current_depth + 1}: scanning {len(all_urls_to_check)} paths...")

                progress = ProgressMonitor(
                    total=len(all_urls_to_check),
                    desc=f"Depth {current_depth + 1}",
                    unit="dir"
                )
                self.current_progress_monitor = progress

                def process_url(url):
                    global scan_interrupted
                    if scan_interrupted:
                        return (None, None)
                    if self.debug:
                        print(f"[DEBUG] Processing URL: {url}")
                    return self.make_request(url, progress)

                # Clear next_level_dirs for this depth
                next_level_dirs = set()
                found_dirs_count = 0

                executor = ThreadPoolExecutor(max_workers=self.threads)
                try:
                    futures = [executor.submit(process_url, url) for url in all_urls_to_check]

                    for future in futures:
                        if scan_interrupted:
                            break

                        try:
                            url_checked, response = future.result(timeout=0.1)
                            if not url_checked or not response:
                                continue

                            status = response.status_code

                            # If it's a "good" code, we consider it discovered and explore it deeper
                            if status in success_codes:
                                # Format URL properly for recursive scanning
                                url_to_add = url_checked if url_checked.endswith('/') else url_checked + '/'

                                if url_to_add not in discovered_dirs:
                                    # Add to global discovered set
                                    discovered_dirs.add(url_to_add)
                                    # Add to next level exploration
                                    next_level_dirs.add(url_to_add)
                                    found_dirs_count += 1

                                    # Ensure this message is always printed, regardless of progress monitor
                                    success_msg = f"[+] Found directory: {url_to_add} [Status: {status}]"
                                    print(success_msg)  # Direct print to ensure visibility

                                    # Also use the progress monitor's print method
                                    if self.use_colors:
                                        path_str = Colors.format_path(url_to_add)
                                        colored_msg = f"{Colors.GREEN}[+]{Colors.RESET} Found new directory: {path_str}[{Colors.format_status(status)}]"
                                        progress.print(colored_msg)
                                else:
                                    if self.debug:
                                        print(f"[DEBUG] Directory already discovered: {url_to_add}")

                            elif status != 404:
                                # If the code is not 404, but not good either: we might still explore it
                                url_to_add = url_checked if url_checked.endswith('/') else url_checked + '/'
                                next_level_dirs.add(url_to_add)
                                if self.debug:
                                    print(
                                        f"[DEBUG] Adding non-404 directory for exploration: {url_to_add} (Status: {status})")

                            else:
                                # It's a real 404, but we might still want to explore it (special case)
                                if hasattr(self, 'soft_404_detector') and self.soft_404_detector:
                                    if not self.soft_404_detector.is_soft_404(url_checked, response):
                                        url_to_add = url_checked if url_checked.endswith('/') else url_checked + '/'
                                        next_level_dirs.add(url_to_add)
                                        if self.debug:
                                            print(f"[DEBUG] Adding potential soft-404 directory: {url_to_add}")

                        except (TimeoutError, concurrent.futures.TimeoutError):
                            continue
                finally:
                    executor.shutdown(
                        wait=not scan_interrupted,
                        cancel_futures=scan_interrupted
                    )

                if scan_interrupted:
                    progress.interrupt()
                    print(f"\n[!] Scan interrupted at depth {current_depth + 1}.")
                    break
                else:
                    progress.close()

                print(f"[*] Depth {current_depth + 1} scan completed.")
                print(f"[*] Found {found_dirs_count} new directories at this depth.")

                if next_level_dirs:
                    # Show some examples of directories found
                    examples = list(next_level_dirs)[:3]
                    example_str = ", ".join(examples)
                    if len(next_level_dirs) > 3:
                        example_str += f" and {len(next_level_dirs) - 3} more..."

                    print(f"[+] {len(next_level_dirs)} directories will be explored in next depth: {example_str}\n")

                    if self.debug:
                        print(f"[DEBUG] Next depth directories ({len(next_level_dirs)}):")
                        for i, dir in enumerate(next_level_dirs):
                            print(f"[DEBUG] {i + 1}. {dir}")
                else:
                    print("[*] No new directories found to explore deeper.\n")
                    break

                # Move to the next depth level with the discovered directories
                current_level_dirs = next_level_dirs.copy()
                current_depth += 1

            # Final results
            if not scan_interrupted:
                print(
                    f"\n[+] Recursive scan completed. Discovered {len(discovered_dirs)} directories in {current_depth} depth levels")

                # Show successful directory discoveries
                if discovered_dirs:
                    print("\n[+] Discovered directories:")
                    # Group by depth level for better visualization
                    base_url = self.target_url.rstrip('/') + '/'
                    by_depth = {}

                    for url in discovered_dirs:
                        if url == base_url:
                            continue
                        rel_path = url.replace(base_url, '')
                        depth = rel_path.count('/')
                        if depth not in by_depth:
                            by_depth[depth] = []
                        by_depth[depth].append(url)

                    # Print by depth level
                    for depth in sorted(by_depth.keys()):
                        print(f"\n  Level {depth}:")
                        for url in sorted(by_depth[depth]):
                            print(f"    {url}")

                # Show debug information if enabled
                if self.debug and discovered_dirs:
                    depth_map = {}
                    base_url = self.target_url.rstrip('/') + '/'

                    for url in discovered_dirs:
                        relative_path = url.replace(base_url, '')
                        depth = relative_path.count('/')
                        if depth not in depth_map:
                            depth_map[depth] = []
                        depth_map[depth].append(url)

                    print("\n[DEBUG] Directories discovered by depth level:")
                    for depth, urls in sorted(depth_map.items()):
                        print(f"[DEBUG] Level {depth}: {len(urls)} directories")
                        if depth <= 2:  # Only show full list for first few levels
                            for url in urls:
                                print(f"[DEBUG]   - {url}")

                if hasattr(self, 'show_forbidden_summary'):
                    self.show_forbidden_summary()
                if hasattr(self, 'show_not_found_summary'):
                    self.show_not_found_summary()

        except Exception as e:
            print(f"\n[-] Error during recursive scan: {e}")
            if self.debug:
                import traceback
                traceback.print_exc()

        finally:
            self.current_progress_monitor = None
            return not scan_interrupted

    def extension_scan(self):
        """Extension scan: searches for files with specific extensions"""
        reset_scan_interruption()

        print("\n" + "="*80)
        if self.use_colors:
            print(f"{Colors.BOLD}{Colors.GREEN}[*] STARTING EXTENSION SCAN{Colors.RESET}")
            print(f"{Colors.GREEN}[*] Threads: {Colors.BOLD}{self.threads}{Colors.RESET}")
        else:
            print("[*] STARTING EXTENSION SCAN")
            print(f"[*] Threads: {self.threads}")
        print("="*80 + "\n")

        try:
            if not self.extensions:
                print("[-] No extensions to scan. Skipping step.")
                return True

            if self.use_colors:
                print(f"{Colors.YELLOW}[*] Extensions to scan: {Colors.BOLD}{', '.join(self.extensions)}{Colors.RESET}")
            else:
                print(f"[*] Extensions to scan: {', '.join(self.extensions)}")

            paths = self.load_wordlist()
            extension_paths = []

            for path in paths:
                for ext in self.extensions:
                    # If the extension doesn't start with a dot, add it
                    ext = ext if ext.startswith('.') else '.' + ext
                    extension_paths.append(f"{path}{ext}")

            total_combinations = len(extension_paths)
            print(f"[*] Total combinations to scan: {total_combinations}")

            # Create progress monitor for all combinations
            progress = ProgressMonitor(
                total=total_combinations,
                desc="Extension Scan",
                unit="ext"
            )
            self.current_progress_monitor = progress

            def scan_with_progress(path):
                global scan_interrupted
                if scan_interrupted:
                    return None
                return self.scan_url(path, progress)

            executor = ThreadPoolExecutor(max_workers=self.threads)
            try:
                futures = [executor.submit(scan_with_progress, path) for path in extension_paths]
                for future in futures:
                    if scan_interrupted:
                        break
                    try:
                        future.result(timeout=0.1)
                    except concurrent.futures.TimeoutError:
                        continue
            finally:
                executor.shutdown(
                    wait=not scan_interrupted,
                    cancel_futures=scan_interrupted,
                )

            # Close the progress bar
            if scan_interrupted:
                progress.interrupt()
            else:
                progress.close()

            if not scan_interrupted:
                # Count only files with extensions in the results
                extension_count = sum(
                    1 for url in self.discovered_urls if any(url.endswith(ext) for ext in self.extensions))
                print(f"\n[+] Extension scan completed. Found {extension_count} files.")

                # Display 403 summary if any
                self.show_forbidden_summary()

                # Display 404 summary if any
                self.show_not_found_summary()

        except Exception as e:
            print(f"\n[-] Error during extension scan: {e}")

        finally:
            self.current_progress_monitor = None
            return not scan_interrupted

    def check_subdomain(self, subdomain, progress_monitor=None):
        """Checks if a subdomain exists and updates the progress"""
        global scan_interrupted
        if scan_interrupted:
            return False

        if self.delay > 0:
            time.sleep(self.delay)

        target_domain = urlparse(self.target_url).netloc
        if ":" in target_domain:  # Handle ports in the domain
            target_domain = target_domain.split(":")[0]

        full_domain = f"{subdomain}.{target_domain}"

        try:
            # First try to resolve with DNS
            answers = dns.resolver.resolve(full_domain, 'A')
            ip = answers[0].to_text()

            # If resolved, try making an HTTP request
            proto = urlparse(self.target_url).scheme
            url = f"{proto}://{full_domain}"

            try:
                response = self.session.get(url, timeout=10, allow_redirects=False)
                status = response.status_code
                content_length = len(response.content)

                # Add to the list of subdomains
                self.discovered_subdomains.add((full_domain, ip, status, content_length))

                # Handle 403 Forbidden responses
                if status == 403:
                    self.forbidden_count += 1
                    self.forbidden_urls.append(url)

                    # Display 403 summary every 10 results or every 5 seconds
                    current_time = time.time()
                    if self.forbidden_count % 10 == 0 or (current_time - self.last_forbidden_report_time) > 5:
                        if self.use_colors:
                            status_str = Colors.format_status(403)
                            msg = f"{status_str} Received {self.forbidden_count} 403 Forbidden responses (last: {url})"
                        else:
                            msg = f"[403] Received {self.forbidden_count} 403 ПравдаForbidden responses (last: {url})"

                        if progress_monitor:
                            progress_monitor.print(msg)
                        else:
                            print(msg)

                        self.last_forbidden_report_time = current_time

                    # Update progress if exists
                    if progress_monitor:
                        progress_monitor.update(1)

                    return True

                # Format the message for found subdomains
                if self.use_colors:
                    domain_str = Colors.format_domain(full_domain)
                    ip_str = Colors.format_ip(f"({ip})")
                    status_str = Colors.format_status(status)
                    size_str = Colors.format_size(f"{content_length} bytes")
                    success_msg = f"{Colors.GREEN}[+]{Colors.RESET} Subdomain found: {domain_str} {ip_str} - {status_str} - {size_str}"
                else:
                    success_msg = f"[+] Subdomain found: {full_domain} ({ip}) - HTTP {status} - {content_length} bytes"

                if progress_monitor:
                    progress_monitor.print(success_msg)
                else:
                    print(success_msg)

                # Update progress if exists
                if progress_monitor:
                    progress_monitor.update(1)

                return True
            except requests.RequestException:
                # If the HTTP request fails but DNS exists, we still consider it exists
                self.discovered_subdomains.add((full_domain, ip, 0, 0))

                # Format the message
                if self.use_colors:
                    domain_str = Colors.format_domain(full_domain)
                    ip_str = Colors.format_ip(f"({ip})")
                    success_msg = f"{Colors.GREEN}[+]{Colors.RESET} Subdomain found: {domain_str} {ip_str} - No HTTP response"
                else:
                    success_msg = f"[+] Subdomain found: {full_domain} ({ip}) - No HTTP response"

                if progress_monitor:
                    progress_monitor.print(success_msg)
                else:
                    print(success_msg)

                # Update progress if exists
                if progress_monitor:
                    progress_monitor.update(1)

                return True

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            # The subdomain does not exist or there is a DNS issue
            # Update progress even if not found
            if progress_monitor:
                progress_monitor.update(1)

            return False

    def subdomain_scan(self):
        """Subdomain scan using the wordlist"""
        reset_scan_interruption()

        print("\n" + "="*80)
        if self.use_colors:
            print(f"{Colors.BOLD}{Colors.BLUE}[*] STARTING SUBDOMAIN SCAN{Colors.RESET}")
            print(f"{Colors.BLUE}[*] Threads: {Colors.BOLD}{self.threads}{Colors.RESET}")
        else:
            print("[*] STARTING SUBDOMAIN SCAN")
            print(f"[*] Threads: {self.threads}")
        print("="*80 + "\n")

        try:
            # Extract the base domain from the URL
            parsed_url = urlparse(self.target_url)
            domain = parsed_url.netloc

            if ":" in domain:  # Remove port if present
                domain = domain.split(":")[0]

            if self.use_colors:
                print(f"{Colors.YELLOW}[*] Target domain: {Colors.BOLD}{domain}{Colors.RESET}")
            else:
                print(f"[*] Target domain: {domain}")

            subdomains = self.load_wordlist()
            total_subdomains = len(subdomains)

            print(f"[*] Checking {total_subdomains} possible subdomains...")

            # Create progress monitor
            progress = ProgressMonitor(total=total_subdomains, desc="Subdomains", unit="sub")
            self.current_progress_monitor = progress

            # Wrapper function to update progress
            def check_with_progress(subdomain):
                global scan_interrupted
                if scan_interrupted:
                    return None
                return self.check_subdomain(subdomain, progress)

            executor = ThreadPoolExecutor(max_workers=self.threads)
            try:
                futures = [executor.submit(check_with_progress, subdomain) for subdomain in subdomains]

                for future in futures:
                    if scan_interrupted:
                        break

                    try:
                        future.result(timeout=0.1)
                    except concurrent.futures.TimeoutError:
                        continue
            finally:
                executor.shutdown(
                    wait=not scan_interrupted,
                    cancel_futures=scan_interrupted,
                )

            # Close the progress bar
            if scan_interrupted:
                progress.interrupt()
                print(f"\n[!] Subdomain scan interrupted by the user.")
            else:
                progress.close()
                print(
                    f"\n[+] Subdomain scan completed. Found {len(self.discovered_subdomains)} active subdomains.")

                # Display 403 summary if any
                self.show_forbidden_summary()

                # Display 404 summary if any
                self.show_not_found_summary()

        except Exception as e:
            print(f"\n[-] Error during subdomain scan: {e}")

        finally:
            self.current_progress_monitor = None
            return not scan_interrupted

    def reset_forbidden_counter(self):
        """Resets the counter for 403 Forbidden responses"""
        self.forbidden_count = 0
        self.forbidden_urls = []
        self.last_forbidden_report_time = time.time()

    def reset_not_found_counter(self):
        """Resets the counter for 404 Not Found responses"""
        self.not_found_count = 0
        self.not_found_urls = []
        self.last_not_found_report_time = time.time()

    def content_scan(self):
        """Scans the content of 200 OK responses for new URLs"""
        reset_scan_interruption()

        print("\n" + "="*80)
        if self.use_colors:
            print(f"{Colors.BOLD}{Colors.YELLOW}[*] STARTING CONTENT SCAN{Colors.RESET}")
            print(f"{Colors.YELLOW}[*] Threads: {Colors.BOLD}{self.threads}{Colors.RESET}")
        else:
            print("[*] STARTING CONTENT SCAN")
            print(f"[*] Threads: {self.threads}")
        print("="*80 + "\n")

        try:
            # Filter URLs with 200 OK responses
            urls_to_scan = [
                url for url, info in self.responses.items()
                if info.get("status") == 200 and info.get("content") is not None
            ]

            if not urls_to_scan:
                print("[-] No 200 OK responses with content to analyze.")
                self.content_scan_done = True
                return True

            print(f"[*] Analyzing content of {len(urls_to_scan)} URLs with 200 OK response...")

            # Create a set to store newly discovered URLs
            new_urls = set()
            already_processed = set(self.discovered_urls)

            # Create progress monitor
            progress = ProgressMonitor(
                total=len(urls_to_scan),
                desc="Content Scan",
                unit="url"
            )
            self.current_progress_monitor = progress

            def process_content(url):
                global scan_interrupted
                if scan_interrupted:
                    return []

                if self.delay > 0:
                    time.sleep(self.delay)

                content = self.responses[url].get("content")
                extracted_urls = self.extract_urls_from_content(url, content)

                discovered_in_content = 0
                for extracted_url in extracted_urls:
                    if extracted_url not in already_processed and extracted_url not in new_urls:
                        new_urls.add(extracted_url)
                        discovered_in_content += 1

                # If new URLs were discovered, display a message
                if discovered_in_content > 0:
                    if self.use_colors:
                        msg = f"{Colors.GREEN}[+]{Colors.RESET} Found {Colors.CYAN}{discovered_in_content}{Colors.RESET} new URLs in {Colors.format_path(url)}"
                    else:
                        msg = f"[+] Found {discovered_in_content} new URLs in {url}"

                    progress.print(msg)

                # Update progress
                progress.update(1)

                return extracted_urls

            # Process the content of all URLs in parallel
            executor = ThreadPoolExecutor(max_workers=self.threads)
            try:
                futures = [executor.submit(process_content, url) for url in urls_to_scan]

                for future in futures:
                    if scan_interrupted:
                        break

                    try:
                        future.result(timeout=0.1)
                    except concurrent.futures.TimeoutError:
                        continue
            finally:
                executor.shutdown(
                    wait=not scan_interrupted,
                    cancel_futures=scan_interrupted,
                )

            # Close the progress bar
            if scan_interrupted:
                progress.interrupt()
                print("\n[!] Content scan interrupted by the user.")
                self.current_progress_monitor = None
                return False
            else:
                progress.close()

            # Verify the new URLs found
            if new_urls and not scan_interrupted:
                print(f"\n[*] Scanning {len(new_urls)} new URLs found in the content...")

                # Create progress monitor for the new URLs
                progress = ProgressMonitor(
                    total=len(new_urls),
                    desc="New URLs",
                    unit="url"
                )
                self.current_progress_monitor = progress

                # Wrapper function to update progress
                def scan_with_progress(url):
                    global scan_interrupted
                    if scan_interrupted:
                        return None
                    return self.scan_url(url, progress)

                executor = ThreadPoolExecutor(max_workers=self.threads)
                try:
                    futures = [executor.submit(scan_with_progress, url) for url in new_urls]

                    for future in futures:
                        if scan_interrupted:
                            break

                        try:
                            future.result(timeout=0.1)
                        except concurrent.futures.TimeoutError:
                            continue
                finally:
                    executor.shutdown(
                        wait=not scan_interrupted,
                        cancel_futures=scan_interrupted,
                    )

                # Close the progress bar
                if scan_interrupted:
                    progress.interrupt()
                    print("\n[!] Scan of new URLs interrupted by the user.")
                else:
                    progress.close()
                    print(f"\n[+] Content scan completed. Discovered {len(new_urls)} new URLs.")

                    # Display 403 summary if any
                    self.show_forbidden_summary()

                    # Display 404 summary if any
                    self.show_not_found_summary()
            elif not scan_interrupted:
                print("\n[*] No new URLs found in the content.")

                # Display 403 summary if any
                self.show_forbidden_summary()

                # Display 404 summary if any
                self.show_not_found_summary()

            # Mark that content scanning has been performed
            self.content_scan_done = True

        except Exception as e:
            print(f"\n[-] Error during content scan: {e}")

        finally:
            self.current_progress_monitor = None
            return not scan_interrupted

    def run_all_scans(self, scan_subdomains=False):
        # Register the SIGINT signal handler (Ctrl+C)
        signal.signal(signal.SIGINT, handle_keyboard_interrupt)

        reset_scan_interruption()



        if self.use_colors:
            print(f"\n{Colors.YELLOW}[*] Starting FuzzStorm against {Colors.BOLD}{self.target_url}{Colors.RESET}")
            print(f"{Colors.YELLOW}[*] Wordlist: {Colors.BOLD}{self.wordlist}{Colors.RESET}")
            print(f"{Colors.YELLOW}[*] Extensions: {Colors.BOLD}{', '.join(self.extensions) if self.extensions else 'None'}{Colors.RESET}")
            print(f"{Colors.YELLOW}[*] Threads: {Colors.BOLD}{self.threads}{Colors.RESET}")
            print(f"{Colors.YELLOW}[*] Delay: {Colors.BOLD}{self.delay}{Colors.RESET} seconds")
            print(f"{Colors.YELLOW}[*] Alternative HTTP method testing: {Colors.BOLD}{'Enabled' if self.test_methods else 'Disabled'}{Colors.RESET}")
            print(f"{Colors.YELLOW}[*] Security analysis: {Colors.BOLD}{'Enabled' if self.security_analysis else 'Disabled'}{Colors.RESET}")
        else:
            print(f"\n[*] Starting FuzzStorm against {self.target_url}")
            print(f"[*] Wordlist: {self.wordlist}")
            print(f"[*] Extensions: {', '.join(self.extensions) if self.extensions else 'None'}")
            print(f"[*] Threads: {self.threads}")
            print(f"[*] Delay: {self.delay} seconds")
            print(f"[*] Alternative HTTP method testing: {'Enabled' if self.test_methods else 'Disabled'}")
            print(f"[*] Security analysis: {'Enabled' if self.security_analysis else 'Disabled'}")

        start_time = time.time()

        # First, scan for subdomains if requested
        if scan_subdomains:
            if not self.subdomain_scan():
                # If interrupted, show message but continue with the next scan
                print(
                    "\n[!] Subdomain scan interrupted by the user. Continuing with the next scan...")
                # Reset the interruption flag for the next scan
                reset_scan_interruption()

        # Execute standard scans
        if not self.normal_scan():
            # If interrupted, show message but continue with the next scan
            print("\n[!] Normal scan interrupted by the user. Continuing with the next scan...")
            # Reset the interruption flag for the next scan
            reset_scan_interruption()

        if not self.recursive_scan():
            # If interrupted, show message but continue with the next scan
            print("\n[!] Recursive scan interrupted by the user. Continuing with the next scan...")
            # Reset the interruption flag for the next scan
            reset_scan_interruption()

        if not self.extension_scan():
            # If interrupted, show message but continue with the next scan
            print("\n[!] Extension scan interrupted by the user. Continuing with the next scan...")
            # Reset the interruption flag for the next scan
            reset_scan_interruption()

        # Execute content scan after standard scans
        if not self.content_scan():
            # If interrupted, show message
            print("\n[!] Content scan interrupted by the user.")
            # No need to reset the flag here as it's the last scan

        # Execute Techackz-based technology and vulnerability analysis
        if self.security_analysis and hasattr(self, 'security_analyzer'):
            self.run_techackz_analysis()

        elapsed_time = time.time() - start_time

        # Display final summary in table format
        print("\n+-----------------------------------------------------------------------------+")
        print("|                              SUMMARY OF RESULTS                             |")
        print("+-----------------------------------------------------------------------------+")
        print(f"| Total scan time: {elapsed_time:.2f} seconds" + " " * (41 - len(f"{elapsed_time:.2f}")) + "|")
        print(f"| Total resources discovered: {len(self.discovered_urls)}" + " " * (
                38 - len(str(len(self.discovered_urls)))) + "|")

        # Count results by status code
        status_counts = {}
        for url, info in self.responses.items():
            status = info["status"]
            if status not in status_counts:
                status_counts[status] = 0
            status_counts[status] += 1

        print("+-----------------------------------------------------------------------------+")
        print("| Status codes found:                                                         |")
        print("+------------------+----------------------------------------------------------+")
        print("| Status Code      | Count                                                    |")
        print("+------------------+----------------------------------------------------------+")

        for status, count in sorted(status_counts.items()):
            status_str = str(status)
            if self.use_colors:
                status_color = Colors.status_color(status)
                status_str = f"{status_color}{status}{Colors.RESET}"

            print(f"| {status_str.ljust(16)} | {str(count).ljust(56)} |")

        print("+------------------+----------------------------------------------------------+")

        # Report found subdomains
        if scan_subdomains and self.discovered_subdomains:
            print("\n+-----------------------------------------------------------------------------+")
            print("|                          SUBDOMAINS FOUND                                   |")
            print("+------------------+---------------+----------------+-------------------------+")
            print("| Subdomain        | IP            | HTTP Status    | Size                    |")
            print("+------------------+---------------+----------------+-------------------------+")

            for subdomain, ip, status, content_length in sorted(self.discovered_subdomains):
                # Truncate subdomain if too long
                sub_display = subdomain
                if len(subdomain) > 16:
                    sub_display = subdomain[:13] + "..."

                status_str = "No response" if not status else f"HTTP {status}"
                content_str = f"{content_length} bytes" if content_length else "-"

                if self.use_colors:
                    sub_color = Colors.GREEN
                    ip_color = Colors.YELLOW
                    status_color = Colors.status_color(status) if status else Colors.RED

                    print(
                        f"| {sub_color}{sub_display.ljust(16)}{Colors.RESET} | {ip_color}{ip.ljust(13)}{Colors.RESET} | {status_color}{status_str.ljust(14)}{Colors.RESET} | {content_str.ljust(23)} |")
                else:
                    print(
                        f"| {sub_display.ljust(16)} | {ip.ljust(13)} | {status_str.ljust(14)} | {content_str.ljust(23)} |")

            print("+------------------+---------------+----------------+-------------------------+")

        # Report alternative methods found
        if self.method_success:
            print("\n+-----------------------------------------------------------------------------+")
            print("|                       ALTERNATIVE HTTP METHODS                             |")
            print("+-----------------------------------------------------------------------------+")

            for url, methods in self.method_success.items():
                print(f"\nURL: {url}")
                print("+--------+----------------+--------+-------------------------+")
                print("| Method | Data Type      | Status | Size                    |")
                print("+--------+----------------+--------+-------------------------+")

                for method, status, content_length, content_type in methods:
                    content_type_str = content_type if content_type else "-"

                    if self.use_colors:
                        status_str = Colors.status_color(status) + str(status) + Colors.RESET
                        print(
                            f"| {Colors.BLUE}{method.ljust(6)}{Colors.RESET} | {content_type_str.ljust(14)} | {status_str.ljust(6)} | {str(content_length).ljust(23)} |")
                    else:
                        print(
                            f"| {method.ljust(6)} | {content_type_str.ljust(14)} | {status.ljust(6)} | {str(content_length).ljust(23)} |")

                print("+--------+----------------+--------+-------------------------+")

        # Display security analysis results if enabled
        if self.security_analysis and hasattr(self, 'security_analyzer'):
            findings = self.security_analyzer.generate_report()
            if findings:
                print("\n+-----------------------------------------------------------------------------+")
                print("|                      DETECTED SECURITY ISSUES                               |")
                print("+-----------------------------------------------------------------------------+")

                for url, issues in findings.items():
                    print(f"\nURL: {url}")

                    # Display missing security headers
                    if "missing_security_headers" in issues:
                        print("\n+-----------------------------------------------------------------------------+")
                        print("| Missing security headers:                                                   |")
                        print("+------------------+----------------------------------------------------------+")
                        print("| Header           | Description                                              |")
                        print("+------------------+----------------------------------------------------------+")

                        for header, description in issues["missing_security_headers"]:
                            # Truncate if description is too long
                            desc_display = description
                            if len(description) > 56:
                                desc_display = description[:53] + "..."

                            header_display = header
                            if len(header) > 16:
                                header_display = header[:13] + "..."

                            print(f"| {header_display.ljust(16)} | {desc_display.ljust(56)} |")

                        print("+------------------+----------------------------------------------------------+")

                    # Display possible vulnerabilities
                    if "vulnerabilities" in issues:
                        print("\n+-----------------------------------------------------------------------------+")
                        print("| Possible vulnerabilities:                                                   |")
                        print("+-----------------------------------------------------------------------------+")

                        for vuln in issues["vulnerabilities"]:
                            desc_display = vuln['description']
                            if len(desc_display) > 75:
                                desc_display = desc_display[:72] + "..."

                            if self.use_colors:
                                print(f"| {Colors.RED}{desc_display.ljust(75)}{Colors.RESET} |")
                            else:
                                print(f"| {desc_display.ljust(75)} |")

                            print("+-----------------------------------------------------------------------------+")
                            print("| Examples found:                                                             |")
                            print("+-----------------------------------------------------------------------------+")

                            for i, match in enumerate(vuln['matches']):
                                if i < 3:  # Limit to 3 samples for brevity
                                    match_display = str(match)
                                    if len(match_display) > 75:
                                        match_display = match_display[:72] + "..."

                                    print(f"| - {match_display.ljust(73)} |")

                            print("+-----------------------------------------------------------------------------+")

                    techackz_data = issues.get("techackz")
                    if techackz_data:
                        technologies = techackz_data.get("technologies", [])
                        vulns = techackz_data.get("vulnerabilities", [])

                        if technologies:
                            print("\n+-----------------------------------------------------------------------------+")
                            print("| Technologies detected by Techackz:                                         |")
                            print("+-----------------------------------------------------------------------------+")
                            for tech in technologies[:5]:
                                tech_display = tech
                                if isinstance(tech, dict):
                                    name = tech.get("name") or tech.get("technology") or "Unknown"
                                    version = tech.get("version") or ""
                                    if version:
                                        tech_display = f"{name} {version}"
                                    else:
                                        tech_display = name
                                if len(str(tech_display)) > 75:
                                    tech_display = str(tech_display)[:72] + "..."
                                print(f"| {str(tech_display).ljust(75)} |")
                            print("+-----------------------------------------------------------------------------+")

                        if vulns:
                            print("\n+-----------------------------------------------------------------------------+")
                            print("| Vulnerabilities reported by Techackz:                                      |")
                            print("+-----------------------------------------------------------------------------+")
                            for vuln in vulns[:5]:
                                if isinstance(vuln, dict):
                                    desc = vuln.get("description") or vuln.get("name") or str(vuln)
                                else:
                                    desc = str(vuln)

                                if len(desc) > 75:
                                    desc = desc[:72] + "..."

                                print(f"| {desc.ljust(75)} |")
                            print("+-----------------------------------------------------------------------------+")

        print("\n+-----------------------------------------------------------------------------+")
        print("|                             END OF REPORT                                   |")
        print("+-----------------------------------------------------------------------------+\n")

        return self.discovered_urls, self.discovered_subdomains

    def export_results(self, filename, format="txt", filtered_urls=None):
        """Exports the results to different formats"""
        try:
            # Use filtered URLs if provided, otherwise use all discovered URLs
            urls_to_export = filtered_urls if filtered_urls is not None else self.discovered_urls

            if format.lower() == "txt":
                with open(filename, 'w') as f:
                    # Write scan results
                    f.write("# FuzzStorm - Scan Results\n\n")

                    # Write discovered URLs
                    f.write(f"## Discovered URLs: {len(urls_to_export)}\n")

                    # Group URLs by status code
                    urls_by_status = {}
                    for url in sorted(urls_to_export):
                        if url in self.responses:
                            status = self.responses[url]["status"]
                            if status not in urls_by_status:
                                urls_by_status[status] = []
                            urls_by_status[status].append(url)

                    # First write URLs with status codes other than 403
                    for status, urls in sorted(urls_by_status.items()):
                        if status != 403:  # Do not include 403 here, we'll do it later
                            f.write(f"\n### Status Code: {status}\n")
                            for url in urls:
                                content_length = self.responses[url]["content_length"]
                                f.write(f"{url} - {content_length} bytes\n")

                    # Write URLs with 403 Forbidden status code
                    if 403 in urls_by_status:
                        f.write(f"\n### Status Code: 403 Forbidden ({len(urls_by_status[403])} results)\n")
                        for url in urls_by_status[403]:
                            content_length = self.responses[url]["content_length"]
                            f.write(f"{url} - {content_length} bytes\n")

                    # Write discovered subdomains
                    if self.discovered_subdomains:
                        f.write("\n\n## Discovered Subdomains\n")
                        for subdomain, ip, status, content_length in sorted(self.discovered_subdomains):
                            status_str = f"HTTP {status}" if status else "No HTTP response"
                            content_str = f"{content_length} bytes" if content_length else ""
                            f.write(f"{subdomain} ({ip}) - {status_str} {content_str}\n")

                    # Write alternative HTTP methods
                    if self.method_success:
                        f.write("\n\n## Alternative HTTP Methods\n")
                        for url, methods in self.method_success.items():
                            f.write(f"\nURL: {url}\n")
                            for method, status, content_length, content_type in methods:
                                content_type_str = f" ({content_type})" if content_type else ""
                                f.write(f"\t- {method}{content_type_str}: {status} - {content_length} bytes\n")

                    # Write security analysis results
                    if self.security_analysis and hasattr(self, 'security_analyzer'):
                        findings = self.security_analyzer.generate_report()
                        if findings:
                            f.write("\n\n## Detected Security Issues\n")
                            for url, issues in findings.items():
                                f.write(f"\nURL: {url}\n")

                                # Display missing security headers
                                if "missing_security_headers" in issues:
                                    f.write("\t- Missing Security Headers:\n")
                                    for header, description in issues["missing_security_headers"]:
                                        f.write(f"\t\t* {header}: {description}\n")

                                # Display possible vulnerabilities
                                if "vulnerabilities" in issues:
                                    f.write("\t- Possible Vulnerabilities:\n")
                                    for vuln in issues["vulnerabilities"]:
                                        f.write(f"\t\t* {vuln['description']}\n")
                                        for i, match in enumerate(vuln['matches']):
                                            if i < 3:
                                                f.write(f"\t\t\t- {match}\n")

                                techackz_data = issues.get("techackz")
                                if techackz_data:
                                    f.write("\t- Techackz Findings:\n")
                                    technologies = techackz_data.get("technologies", [])
                                    if technologies:
                                        f.write("\t\t* Technologies:\n")
                                        for tech in technologies[:5]:
                                            tech_display = tech
                                            if isinstance(tech, dict):
                                                name = tech.get("name") or tech.get("technology") or "Unknown"
                                                version = tech.get("version") or ""
                                                tech_display = f"{name} {version}".strip()
                                            f.write(f"\t\t\t- {tech_display}\n")

                                    vulns = techackz_data.get("vulnerabilities", [])
                                    if vulns:
                                        f.write("\t\t* Vulnerabilities:\n")
                                        for vuln in vulns[:5]:
                                            if isinstance(vuln, dict):
                                                desc = vuln.get("description") or vuln.get("name") or str(vuln)
                                            else:
                                                desc = str(vuln)
                                            f.write(f"\t\t\t- {desc}\n")

            elif format.lower() == "json":
                # Create results dictionary
                results = {
                    "target_url": self.target_url,
                    "scan_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "discovered_urls": list(sorted(self.discovered_urls)),
                    "discovered_subdomains": [
                        {
                            "subdomain": subdomain,
                            "ip": ip,
                            "http_status": status,
                            "content_length": content_length
                        }
                        for subdomain, ip, status, content_length in sorted(self.discovered_subdomains)
                    ],
                    "soft_404s": list(sorted(getattr(self, 'soft_404s', set()))),
                    "real_200s": list(sorted(getattr(self, 'real_200s', set()))),
                    "http_methods": {
                        url: [
                            {
                                "method": method,
                                "status": status,
                                "content_length": content_length,
                                "content_type": content_type
                            }
                            for method, status, content_length, content_type in methods
                        ]
                        for url, methods in self.method_success.items()
                    },
                    "responses": {
                        url: {
                            "status": info["status"],
                            "content_length": info["content_length"],
                            "headers": info["headers"]
                        }
                        for url, info in self.responses.items()
                    }
                }

                # Add status code summary
                status_summary = {}
                for url, info in self.responses.items():
                    status = info["status"]
                    if status not in status_summary:
                        status_summary[status] = 0
                    status_summary[status] += 1

                results["status_summary"] = status_summary

                # Add security findings if available
                if self.security_analysis and hasattr(self, 'security_analyzer'):
                    security_findings = self.security_analyzer.generate_report()
                    if security_findings:
                        results["security_findings"] = security_findings

                # Save as JSON
                with open(filename, 'w') as f:
                    json.dump(results, f, indent=2)

            elif format.lower() == "csv":
                # Write discovered URLs
                with open(filename, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(["URL", "Status", "Size", "Headers", "Vulnerabilities"])

                    for url in sorted(self.discovered_urls):
                        # Gather information if available
                        if url in self.responses:
                            info = self.responses[url]
                            status = info["status"]
                            content_length = info["content_length"]
                            headers = "; ".join([f"{k}: {v}" for k, v in info["headers"].items()])
                        else:
                            status = "N/A"
                            content_length = "N/A"
                            headers = ""

                        # Gather vulnerabilities if available
                        vulnerabilities = ""
                        techackz_summary = ""
                        if self.security_analysis and hasattr(self, 'security_analyzer'):
                            findings = self.security_analyzer.generate_report()
                            if url in findings:
                                if "vulnerabilities" in findings[url]:
                                    vuln_list = [v["description"] for v in findings[url]["vulnerabilities"]]
                                    vulnerabilities = "; ".join(vuln_list)

                                techackz_data = findings[url].get("techackz")
                                if techackz_data:
                                    tech_names = []
                                    for tech in techackz_data.get("technologies", [])[:3]:
                                        if isinstance(tech, dict):
                                            name = tech.get("name") or tech.get("technology") or "Unknown"
                                            version = tech.get("version") or ""
                                            tech_names.append(f"{name} {version}".strip())
                                        else:
                                            tech_names.append(str(tech))

                                    vuln_names = []
                                    for vuln in techackz_data.get("vulnerabilities", [])[:3]:
                                        if isinstance(vuln, dict):
                                            vuln_names.append(vuln.get("description") or vuln.get("name") or str(vuln))
                                        else:
                                            vuln_names.append(str(vuln))

                                    techackz_parts = []
                                    if tech_names:
                                        techackz_parts.append(f"Tech: {', '.join(tech_names)}")
                                    if vuln_names:
                                        techackz_parts.append(f"Vulns: {', '.join(vuln_names)}")
                                    techackz_summary = " | ".join(techackz_parts)

                        writer.writerow([url, status, content_length, headers, "; ".join(filter(None, [vulnerabilities, techackz_summary]))])

            print(f"\n[+] Results exported in {format.upper()} format to {filename}")
            return True

        except Exception as e:
            print(f"Error exporting results: {e}")
            return False

    def _get_content_as_string(self, content):
        """Converts response content to string"""
        if isinstance(content, bytes):
            try:
                return content.decode('utf-8')
            except UnicodeDecodeError:
                try:
                    return content.decode('latin-1')
                except:
                    return ""
        return str(content)

    def apply_exclusion_filters(self, status_codes=None, lines=None, regexp=None, size=None, time=None, words=None,
                                mode="or"):
        """
        Filters discovered URLs by excluding those that match the specified criteria.

        Args:
            status_codes (str): HTTP status codes to exclude (e.g., "200-299,301,302")
            lines (str): Number of lines in the response to exclude (e.g., ">10", "<100", "=50")
            regexp (str): Regular expression to exclude matching responses
            size (str): Response size in bytes to exclude (e.g., ">1000", "<5000")
            time (str): Response time in milliseconds to exclude (e.g., ">100", "<300")
            words (str): Number of words in the response to exclude (e.g., ">100", "<1000")
            mode (str): Filter operation mode: "and" or "or"

        Returns:
            set: Set of URLs that do NOT match the filters (exclusion)
        """
        # Start with all discovered URLs
        filtered_urls = set(self.discovered_urls)

        # Parse status codes
        excluded_status_codes = set()
        if status_codes:
            if status_codes.lower() == "all":
                # Exclude all status codes (results in empty set)
                return set()
            else:
                # Process ranges (e.g., "200-299") and individual values
                for part in status_codes.split(','):
                    if '-' in part:
                        start, end = map(int, part.split('-'))
                        excluded_status_codes.update(range(start, end + 1))
                    else:
                        excluded_status_codes.add(int(part))

        # URLs to exclude
        urls_to_exclude = set()

        # For each discovered URL, apply exclusion filters
        for url in self.discovered_urls:
            # Get response information
            if url not in self.responses:
                continue

            info = self.responses[url]
            match_results = []

            # Filter by status code
            if status_codes and info.get("status"):
                match_results.append(info.get("status") in excluded_status_codes)

            # Filter by number of lines
            if lines and info.get("content"):
                content_str = self._get_content_as_string(info.get("content"))
                line_count = len(content_str.splitlines())
                match_results.append(self._compare_numeric(line_count, lines))

            # Filter by regular expression
            if regexp and info.get("content"):
                content_str = self._get_content_as_string(info.get("content"))
                try:
                    pattern = re.compile(regexp)
                    match_results.append(bool(pattern.search(content_str)))
                except re.error:
                    # If the regular expression is invalid, it doesn't match
                    match_results.append(False)

            # Filter by response size
            if size and info.get("content_length") is not None:
                match_results.append(self._compare_numeric(info.get("content_length"), size))

            # Filter by response time
            if time and info.get("response_time") is not None:
                match_results.append(self._compare_numeric(info.get("response_time"), time))

            # Filter by number of words
            if words and info.get("content"):
                content_str = self._get_content_as_string(info.get("content"))
                word_count = len(content_str.split())
                match_results.append(self._compare_numeric(word_count, words))

            # Apply the operation mode to determine if the URL is excluded
            if mode.lower() == "and":
                # All filters must match to exclude
                if match_results and all(match_results):
                    urls_to_exclude.add(url)
            else:  # "or" is the default
                # At least one filter must match to exclude
                if match_results and any(match_results):
                    urls_to_exclude.add(url)

        # Return the set of original URLs minus those matching the filters
        return filtered_urls - urls_to_exclude

    def extract_urls_from_content(self, url, content):
        """Extracts URLs from the content of an HTTP response"""
        if isinstance(content, bytes):
            try:
                content_str = content.decode('utf-8')
            except UnicodeDecodeError:
                try:
                    content_str = content.decode('latin-1')
                except:
                    return []
        else:
            content_str = str(content)

        # Regex to find URLs in the content
        # Looks for both absolute and relative URLs
        url_patterns = [
            # Absolute URLs (http:// or https://)
            r'https?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
            # Relative URLs starting with /
            r'href=[\'"]/((?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+)[\'"]',
            # Relative URLs not starting with /
            r'href=[\'"](?!https?://)((?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+)[\'"]',
            # Other links like src=
            r'src=[\'"]/((?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+)[\'"]'
        ]

        found_urls = set()

        for pattern in url_patterns:
            matches = re.findall(pattern, content_str)

            for match in matches:
                if isinstance(match, tuple):  # May return groups as tuples
                    match = match[0]

                # Handle absolute and relative URLs
                if match.startswith(('http://', 'https://')):
                    # Absolute URL
                    found_urls.add(match)
                elif match.startswith('/'):
                    # Relative URL with /
                    base_url = '{uri.scheme}://{uri.netloc}'.format(uri=urlparse(url))
                    found_urls.add(base_url + match)
                elif match.startswith(('?', '#')):
                    # Query parameters or fragments - ignore
                    continue
                else:
                    # Relative URL without /
                    found_urls.add(urljoin(url, match))

        # Filter URLs that do not belong to the target domain
        target_domain = urlparse(self.target_url).netloc
        filtered_urls = [
            u for u in found_urls
            if urlparse(u).netloc == target_domain or not urlparse(u).netloc
        ]

        # Normalize URLs
        normalized_urls = []
        for u in filtered_urls:
            # If it has no netloc, it's a relative URL
            if not urlparse(u).netloc:
                u = urljoin(url, u)
            # Remove fragments
            u = u.split('#')[0]
            normalized_urls.append(u)

        return list(set(normalized_urls))

    def detect_soft_404s(self, threshold=0.9, proxy=None):
        """
        Detects soft 404 responses among URLs with status code 200.

        Args:
            threshold (float): Similarity threshold to consider a page as a soft 404
            proxy (str): Proxy for requests (will inherit the proxy/Tor configured in FuzzStorm)

        Returns:
            tuple: (soft 404 URLs, real 200 URLs)
        """
        if not SOFT_404_DETECTOR_AVAILABLE:
            print("\n[-] Error: Unable to import soft 404 detector.")
            print("    Ensure that the detect_soft_404.py file is in the same directory.")
            return set(), set()

        print(f"\n[+] Starting soft 404 detection...")

        # Filter URLs with status code 200
        urls_200 = {url for url, info in self.responses.items()
                    if info.get("status") == 200}

        if not urls_200:
            print("[-] No 200 OK responses to analyze.")
            return set(), set()

        print(f"[*] Analyzing {len(urls_200)} URLs with 200 OK response...")

        # Configure proxy (use the same as FuzzStorm)
        current_proxy = proxy
        if not current_proxy:
            if self.proxy:
                current_proxy = self.proxy

        # Initialize the detector
        detector = Soft404Detector(
            target_url=self.target_url,
            threshold=threshold,
            proxy=current_proxy,
            user_agent=self.session.headers.get('User-Agent'),
            debug=self.debug
        )

        # Results
        soft_404s = set()
        real_200s = set()

        # Create a progress monitor
        progress = ProgressMonitor(
            total=len(urls_200),
            desc="Soft 404 Detection",
            unit="URL"
        )
        self.current_progress_monitor = progress

        # Process each URL
        for url in urls_200:
            try:
                is_soft_404 = detector.detect_soft_404(url)

                if is_soft_404:
                    soft_404s.add(url)
                    if self.use_colors:
                        progress.print(f"{Colors.YELLOW}[SOFT 404]{Colors.RESET} {url}")
                    else:
                        progress.print(f"[SOFT 404] {url}")
                else:
                    real_200s.add(url)
                    if self.use_colors:
                        progress.print(f"{Colors.GREEN}[REAL 200]{Colors.RESET} {url}")
                    else:
                        progress.print(f"[REAL 200] {url}")

                # Update progress
                progress.update(1)

            except Exception as e:
                progress.print(f"Error verifying {url}: {e}")
                progress.update(1)

        # Close progress
        progress.close()

        # Display summary
        print(f"\n[*] Soft 404 detection summary:")
        print(f"    - URLs verified: {len(urls_200)}")
        print(f"    - Soft 404s detected: {len(soft_404s)}")
        print(f"    - Real 200 URLs: {len(real_200s)}")

        return soft_404s, real_200s

    def export_html_report(self, filename):
        """Exports the results to a standalone HTML file with embedded CSS and JS"""
        try:
            # Embedded CSS with hacker/cyberpunk theme
            css = """
                <style>
                    :root {
                        --main-bg-color: #111927;
                        --card-bg-color: #1a2332;
                        --accent-color: #00ff8c;
                        --accent-color-dark: #00cc6a;
                        --text-color: #e1e6f0;
                        --text-muted: #8792a8;
                        --border-color: #2e3a4f;
                        --success-color: #07d89d;
                        --warning-color: #ffd166;
                        --danger-color: #ff5f5f;
                        --info-color: #3a86ff;
                        --card-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
                        --terminal-bg: #0c0c0c;
                    }

                    * {
                        box-sizing: border-box;
                        margin: 0;
                        padding: 0;
                    }

                    body {
                        font-family: 'Roboto Mono', 'Consolas', monospace;
                        background-color: var(--main-bg-color);
                        background-image: 
                            radial-gradient(circle at 25px 25px, rgba(0, 255, 140, 0.15) 2%, transparent 0%), 
                            radial-gradient(circle at 75px 75px, rgba(58, 134, 255, 0.15) 2%, transparent 0%);
                        background-size: 100px 100px;
                        color: var(--text-color);
                        line-height: 1.6;
                        padding: 0;
                        margin: 0;
                    }

                    .container {
                        max-width: 1200px;
                        margin: 30px auto;
                        padding: 0 20px;
                    }

                    .card {
                        background-color: var(--card-bg-color);
                        border-radius: 8px;
                        box-shadow: var(--card-shadow);
                        margin-bottom: 30px;
                        overflow: hidden;
                        border: 1px solid var(--border-color);
                        position: relative;
                    }

                    .card::before {
                        content: '';
                        position: absolute;
                        top: 0;
                        left: 0;
                        width: 100%;
                        height: 2px;
                        background: linear-gradient(90deg, var(--accent-color) 0%, rgba(58, 134, 255, 1) 100%);
                    }

                    h1, h2, h3, h4 {
                        color: var(--accent-color);
                        font-weight: 700;
                        margin-bottom: 20px;
                    }

                    h1 {
                        text-align: center;
                        text-transform: uppercase;
                        letter-spacing: 2px;
                        padding: 20px 0;
                        font-size: 2.2rem;
                        text-shadow: 0 0 10px rgba(0, 255, 140, 0.5);
                        margin-bottom: 30px;
                    }

                    h2 {
                        font-size: 1.5rem;
                        border-bottom: 1px solid var(--border-color);
                        padding-bottom: 10px;
                        margin-top: 40px;
                    }

                    h3 {
                        font-size: 1.2rem;
                        margin-top: 30px;
                    }

                    .header {
                        background-color: var(--card-bg-color);
                        padding: 30px 20px;
                        border-radius: 8px;
                        margin-bottom: 30px;
                        text-align: center;
                        position: relative;
                        overflow: hidden;
                    }

                    .header::before, .header::after {
                        content: '';
                        position: absolute;
                        width: 200px;
                        height: 200px;
                        border-radius: 50%;
                    }

                    .header::before {
                        background: radial-gradient(rgba(0, 255, 140, 0.15), transparent 70%);
                        top: -100px;
                        left: -100px;
                    }

                    .header::after {
                        background: radial-gradient(rgba(58, 134, 255, 0.15), transparent 70%);
                        bottom: -100px;
                        right: -100px;
                    }

                    .logo {
                        margin-bottom: 20px;
                        font-size: 3rem;
                        font-weight: 900;
                        text-transform: uppercase;
                        letter-spacing: 3px;
                        background: linear-gradient(90deg, var(--accent-color) 0%, rgba(58, 134, 255, 1) 100%);
                        -webkit-background-clip: text;
                        background-clip: text;
                        color: transparent;
                        text-shadow: 0px 2px 5px rgba(0, 0, 0, 0.5);
                        animation: text-flicker 5s infinite;
                    }

                    .subtitle {
                        color: var(--text-muted);
                        font-size: 1rem;
                        font-style: italic;
                        margin-bottom: 10px;
                    }

                    .section {
                        padding: 25px;
                        margin-bottom: 30px;
                        background-color: var(--card-bg-color);
                        border-radius: 8px;
                        box-shadow: var(--card-shadow);
                        border: 1px solid var(--border-color);
                    }

                    .terminal-section {
                        background-color: var(--terminal-bg);
                        border: 1px solid var(--accent-color);
                        border-radius: 6px;
                        padding: 20px;
                        font-family: 'Courier New', monospace;
                        overflow: hidden;
                        position: relative;
                    }

                    .terminal-header {
                        position: absolute;
                        top: 0;
                        left: 0;
                        right: 0;
                        background-color: var(--accent-color);
                        color: var(--terminal-bg);
                        padding: 5px 10px;
                        font-size: 12px;
                        font-weight: bold;
                    }

                    .terminal-content {
                        margin-top: 30px;
                    }

                    pre {
                        white-space: pre-wrap;
                        word-wrap: break-word;
                        font-family: 'Courier New', monospace;
                        font-size: 0.9rem;
                    }

                    code {
                        font-family: 'Courier New', monospace;
                        background-color: rgba(0, 0, 0, 0.2);
                        padding: 2px 4px;
                        border-radius: 3px;
                    }

                    table {
                        width: 100%;
                        border-collapse: collapse;
                        margin: 20px 0;
                        font-size: 0.9rem;
                        border: 1px solid var(--border-color);
                        border-radius: 8px;
                        overflow: hidden;
                    }

                    th, td {
                        padding: 12px 15px;
                        text-align: left;
                    }

                    th {
                        background-color: rgba(0, 0, 0, 0.2);
                        color: var(--accent-color);
                        font-weight: bold;
                        text-transform: uppercase;
                        font-size: 0.8rem;
                        letter-spacing: 1px;
                        border-bottom: 1px solid var(--border-color);
                    }

                    tr {
                        border-bottom: 1px solid var(--border-color);
                        transition: all 0.3s ease;
                    }

                    tr:nth-child(even) {
                        background-color: rgba(0, 0, 0, 0.1);
                    }

                    tr:hover {
                        background-color: rgba(0, 255, 140, 0.05);
                    }

                    td {
                        border-right: 1px solid var(--border-color);
                    }

                    td:last-child {
                        border-right: none;
                    }

                    .code-200 { color: var(--success-color); font-weight: bold; }
                    .code-300 { color: var(--info-color); font-weight: bold; }
                    .code-400 { color: var(--warning-color); font-weight: bold; }
                    .code-403 { color: var(--warning-color); font-weight: bold; }
                    .code-404 { color: var(--text-muted); }
                    .code-500 { color: var(--danger-color); font-weight: bold; }

                    .warning { color: var(--warning-color); }
                    .error { color: var(--danger-color); }
                    .success { color: var(--success-color); }
                    .info { color: var(--info-color); }

                    .url-list {
                        max-height: 500px;
                        overflow-y: auto;
                        border: 1px solid var(--border-color);
                        padding: 10px;
                        border-radius: 8px;
                        background-color: rgba(0, 0, 0, 0.2);
                        margin: 20px 0;
                    }

                    /* Style scrollbar */
                    .url-list::-webkit-scrollbar {
                        width: 10px;
                    }

                    .url-list::-webkit-scrollbar-track {
                        background: var(--main-bg-color);
                    }

                    .url-list::-webkit-scrollbar-thumb {
                        background: var(--accent-color-dark);
                        border-radius: 5px;
                    }

                    .url-list::-webkit-scrollbar-thumb:hover {
                        background: var(--accent-color);
                    }

                    .collapsible {
                        background-color: rgba(0, 0, 0, 0.2);
                        color: var(--text-color);
                        cursor: pointer;
                        padding: 18px;
                        width: 100%;
                        border: 1px solid var(--border-color);
                        text-align: left;
                        outline: none;
                        font-size: 15px;
                        border-radius: 8px;
                        margin-bottom: 5px;
                        transition: all 0.3s ease;
                        position: relative;
                        overflow: hidden;
                    }

                    .collapsible::after {
                        content: '+';
                        color: var(--accent-color);
                        font-weight: bold;
                        float: right;
                        margin-left: 5px;
                        font-size: 1.2rem;
                    }

                    .active::after {
                        content: '-';
                    }

                    .collapsible:hover {
                        background-color: rgba(0, 255, 140, 0.05);
                        border-color: var(--accent-color);
                    }

                    .active {
                        background-color: rgba(0, 0, 0, 0.3);
                        border-bottom-left-radius: 0;
                        border-bottom-right-radius: 0;
                        border-bottom: none;
                    }

                    .content {
                        padding: 0 18px;
                        max-height: 0;
                        overflow: hidden;
                        transition: max-height 0.3s ease;
                        background-color: rgba(0, 0, 0, 0.2);
                        border-left: 1px solid var(--border-color);
                        border-right: 1px solid var(--border-color);
                        border-bottom: 1px solid var(--border-color);
                        border-bottom-left-radius: 8px;
                        border-bottom-right-radius: 8px;
                    }

                    .chart-container {
                        position: relative;
                        height: 350px;
                        margin: 30px 0;
                        padding: 20px;
                        background-color: rgba(0, 0, 0, 0.2);
                        border-radius: 8px;
                        border: 1px solid var(--border-color);
                    }

                    .footer {
                        text-align: center;
                        margin-top: 50px;
                        padding: 20px 0;
                        color: var(--text-muted);
                        font-size: 0.9rem;
                        border-top: 1px solid var(--border-color);
                    }

                    .badge {
                        display: inline-block;
                        padding: 5px 10px;
                        border-radius: 20px;
                        font-size: 0.8rem;
                        margin-right: 5px;
                        font-weight: bold;
                    }

                    .badge-success { 
                        background-color: rgba(7, 216, 157, 0.2);
                        color: var(--success-color);
                        border: 1px solid var(--success-color);
                    }

                    .badge-warning {
                        background-color: rgba(255, 209, 102, 0.2);
                        color: var(--warning-color);
                        border: 1px solid var(--warning-color);
                    }

                    .badge-danger {
                        background-color: rgba(255, 95, 95, 0.2);
                        color: var(--danger-color);
                        border: 1px solid var(--danger-color);
                    }

                    .badge-info {
                        background-color: rgba(58, 134, 255, 0.2);
                        color: var(--info-color);
                        border: 1px solid var(--info-color);
                    }

                    .vulnerability {
                        background-color: rgba(255, 95, 95, 0.05);
                        border-left: 4px solid var(--danger-color);
                        padding: 15px;
                        margin-bottom: 20px;
                        border-radius: 4px;
                    }

                    .stats-grid {
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                        gap: 20px;
                        margin: 30px 0;
                    }

                    .stat-card {
                        background-color: rgba(0, 0, 0, 0.2);
                        border-radius: 8px;
                        padding: 20px;
                        border: 1px solid var(--border-color);
                        text-align: center;
                    }

                    .stat-value {
                        font-size: 2.5rem;
                        font-weight: bold;
                        margin: 10px 0;
                        font-family: 'Roboto Mono', monospace;
                        color: var(--accent-color);
                    }

                    .stat-title {
                        color: var(--text-muted);
                        font-size: 0.9rem;
                        text-transform: uppercase;
                        letter-spacing: 1px;
                    }

                    /* Style for clickable URLs */
                    .url-link {
                        color: var(--text-color);
                        text-decoration: none;
                        border-bottom: 1px dotted var(--accent-color-dark);
                        transition: all 0.2s ease;
                        cursor: pointer;
                    }

                    .url-link:hover {
                        color: var(--accent-color);
                        border-bottom: 1px solid var(--accent-color);
                    }

                    /* For all links */
                    a {
                        color: var(--text-color);
                        text-decoration: none;
                        transition: color 0.2s ease;
                    }

                    a:hover {
                        color: var(--accent-color);
                    }

                    .typing-effect {
                        border-right: 2px solid var(--accent-color);
                        white-space: nowrap;
                        overflow: hidden;
                        animation: typing 3.5s steps(40, end), blink-caret 0.75s step-end infinite;
                    }

                    @keyframes typing {
                        from { width: 0 }
                        to { width: 100% }
                    }

                    @keyframes blink-caret {
                        from, to { border-color: transparent }
                        50% { border-color: var(--accent-color); }
                    }

                    @keyframes text-flicker {
                        0% { opacity: 1; }
                        3% { opacity: 0.8; }
                        6% { opacity: 1; }
                        7% { opacity: 0.9; }
                        8% { opacity: 1; }
                        9% { opacity: 0.9; }
                        10% { opacity: 1; }
                        70% { opacity: 1; }
                        72% { opacity: 0.9; }
                        74% { opacity: 1; }
                        100% { opacity: 1; }
                    }

                    /* Responsive styles */
                    @media (max-width: 768px) {
                        .stats-grid {
                            grid-template-columns: 1fr;
                        }

                        .container {
                            padding: 0 10px;
                        }

                        .section {
                            padding: 15px;
                        }

                        table {
                            display: block;
                            overflow-x: auto;
                        }
                    }
                </style>
                """

            # Embedded JavaScript
            javascript = """
                <script>
                    document.addEventListener('DOMContentLoaded', function() {
                        // Functionality for collapsible elements
                        var coll = document.getElementsByClassName("collapsible");
                        for (var i = 0; i < coll.length; i++) {
                            coll[i].addEventListener("click", function() {
                                this.classList.toggle("active");
                                var content = this.nextElementSibling;

                                // Use max-height for smooth animation
                                if (content.style.maxHeight) {
                                    content.style.maxHeight = null;
                                    content.style.padding = "0 18px";
                                } else {
                                    content.style.maxHeight = content.scrollHeight + 100 + "px";
                                    content.style.padding = "18px";
                                }
                            });
                        }

                        // Generate charts using Chart.js
                        generateStatusChart();
                        addTypewriterEffect();

                        // Add line numbers to code elements (if present)
                        document.querySelectorAll('pre code').forEach(function(block) {
                            addLineNumbers(block);
                        });

                        // Animate counters in stats-cards
                        animateStatCounters();
                    });

                    // Function to add typewriter effect
                    function addTypewriterEffect() {
                        const elements = document.querySelectorAll('.typing-effect');
                        elements.forEach(el => {
                            const text = el.textContent;
                            el.textContent = '';
                            let i = 0;
                            const speed = 50; // typing speed in ms

                            function typeWriter() {
                                if (i < text.length) {
                                    el.textContent += text.charAt(i);
                                    i++;
                                    setTimeout(typeWriter, speed);
                                }
                            }

                            // Start typing after a delay
                            setTimeout(typeWriter, 500);
                        });
                    }

                    // Animate counters in stat cards
                    function animateStatCounters() {
                        const counterElements = document.querySelectorAll('.stat-value');

                        counterElements.forEach(counter => {
                            const target = parseInt(counter.getAttribute('data-target'));
                            const duration = 2000; // ms
                            const step = Math.ceil(target / (duration / 20)); // 20ms per step
                            let current = 0;

                            const updateCounter = () => {
                                current += step;
                                if (current >= target) {
                                    counter.textContent = target;
                                    return;
                                }
                                counter.textContent = current;
                                setTimeout(updateCounter, 20);
                            };

                            updateCounter();
                        });
                    }

                    // Function to add line numbers to code
                    function addLineNumbers(codeBlock) {
                        const lines = codeBlock.textContent.split('\\n');
                        codeBlock.innerHTML = '';

                        for (let i = 0; i < lines.length; i++) {
                            const lineNum = document.createElement('span');
                            lineNum.classList.add('line-number');
                            lineNum.textContent = i + 1;

                            const lineContent = document.createElement('span');
                            lineContent.classList.add('line-content');
                            lineContent.textContent = lines[i];

                            const lineWrapper = document.createElement('div');
                            lineWrapper.classList.add('line');
                            lineWrapper.appendChild(lineNum);
                            lineWrapper.appendChild(lineContent);

                            codeBlock.appendChild(lineWrapper);
                        }
                    }

                    // Function to generate status code chart
                    function generateStatusChart() {
                        // Check if the canvas element for the chart exists
                        var ctx = document.getElementById('statusChart');
                        if (!ctx) return;

                        // Get chart data from the status code table
                        var labels = [];
                        var data = [];
                        var colors = [];
                        var hoverColors = [];

                        var table = document.getElementById('statusTable');
                        if (table) {
                            for (var i = 1; i < table.rows.length; i++) {
                                var statusCode = table.rows[i].cells[0].innerText;
                                var count = parseInt(table.rows[i].cells[1].innerText);

                                labels.push("HTTP " + statusCode);
                                data.push(count);

                                // Assign colors based on status code - using CSS variables
                                let color, hoverColor;

                                if (statusCode.startsWith('2')) {
                                    color = 'rgba(7, 216, 157, 0.7)';
                                    hoverColor = 'rgba(7, 216, 157, 1)';
                                } else if (statusCode.startsWith('3')) {
                                    color = 'rgba(58, 134, 255, 0.7)';
                                    hoverColor = 'rgba(58, 134, 255, 1)';
                                } else if (statusCode.startsWith('4')) {
                                    if (statusCode === '403') {
                                        color = 'rgba(255, 209, 102, 0.7)';
                                        hoverColor = 'rgba(255, 209, 102, 1)';
                                    } else if (statusCode === '404') {
                                        color = 'rgba(135, 146, 168, 0.7)';
                                        hoverColor = 'rgba(135, 146, 168, 1)';
                                    } else {
                                        color = 'rgba(255, 209, 102, 0.7)';
                                        hoverColor = 'rgba(255, 209, 102, 1)';
                                    }
                                } else if (statusCode.startsWith('5')) {
                                    color = 'rgba(255, 95, 95, 0.7)';
                                    hoverColor = 'rgba(255, 95, 95, 1)';
                                } else {
                                    color = 'rgba(135, 146, 168, 0.7)';
                                    hoverColor = 'rgba(135, 146, 168, 1)';
                                }

                                colors.push(color);
                                hoverColors.push(hoverColor);
                            }
                        }

                        // Create the chart if there is data
                        if (labels.length > 0) {
                            var chart = new Chart(ctx, {
                                type: 'doughnut',
                                data: {
                                    labels: labels,
                                    datasets: [{
                                        data: data,
                                        backgroundColor: colors,
                                        hoverBackgroundColor: hoverColors,
                                        borderWidth: 2,
                                        borderColor: '#1a2332'
                                    }]
                                },
                                options: {
                                    responsive: true,
                                    maintainAspectRatio: false,
                                    legend: {
                                        position: 'right',
                                        labels: {
                                            fontColor: '#e1e6f0',
                                            fontFamily: "'Roboto Mono', monospace",
                                            padding: 15
                                        }
                                    },
                                    title: {
                                        display: true,
                                        text: 'Status Code Distribution',
                                        fontColor: '#00ff8c',
                                        fontSize: 16,
                                        fontFamily: "'Roboto Mono', monospace"
                                    },
                                    tooltips: {
                                        backgroundColor: 'rgba(0, 0, 0, 0.7)',
                                        titleFontColor: '#00ff8c',
                                        bodyFontColor: '#e1e6f0',
                                        borderColor: '#00ff8c',
                                        borderWidth: 1,
                                        callbacks: {
                                            label: function(tooltipItem, data) {
                                                var dataset = data.datasets[tooltipItem.datasetIndex];
                                                var total = dataset.data.reduce((previous, current) => previous + current);
                                                var currentValue = dataset.data[tooltipItem.index];
                                                var percentage = Math.round((currentValue/total) * 100);
                                                return data.labels[tooltipItem.index] + ': ' + currentValue + ' (' + percentage + '%)';
                                            }
                                        }
                                    },
                                    animation: {
                                        animateScale: true,
                                        animateRotate: true,
                                        duration: 2000,
                                        easing: 'easeOutQuart'
                                    }
                                }
                            });

                            // Add hover effects to legend items
                            ctx.parentNode.querySelectorAll('li').forEach(function(item) {
                                item.style.transition = 'transform 0.2s ease';
                                item.addEventListener('mouseover', function() {
                                    this.style.transform = 'translateX(5px)';
                                });
                                item.addEventListener('mouseout', function() {
                                    this.style.transform = 'translateX(0)';
                                });
                            });
                        }
                    }
                </script>
                """

            # External Chart.js dependency for charts
            chart_js = '<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>'

            # Calculate total resources found (excluding 404s and soft 404s)
            valid_resources = sum(1 for url in self.discovered_urls
                                  if url in self.responses
                                  and self.responses[url]["status"] != 404
                                  and not (self.responses[url]["status"] == 200
                                           and hasattr(self, 'soft_404s')
                                           and url in self.soft_404s))

            # Generate HTML content
            with open(filename, 'w', encoding='utf-8') as f:
                # HTML header
                f.write(f"""<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>FuzzStorm - Scan Report</title>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Roboto+Mono:wght@400;700&display=swap" rel="stylesheet">
        {css}
        {chart_js}
    </head>
    <body>
        <div class="container">
            <div class="header card">
                <div class="logo">FuzzStorm</div>
                <div class="subtitle typing-effect">Web Security Scan Report</div>
                <p>Generated on {datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")}</p>
            </div>

            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-title">Resources Found</div>
                    <div class="stat-value" data-target="{valid_resources}">0</div>
                </div>
                <div class="stat-card">
                    <div class="stat-title">Status Codes</div>
                    <div class="stat-value" data-target="{len(set([info.get('status', 0) for info in self.responses.values()]))}">0</div>
                </div>
                <div class="stat-card">
                    <div class="stat-title">Subdomains</div>
                    <div class="stat-value" data-target="{len(self.discovered_subdomains)}">0</div>
                </div>
                <div class="stat-card">
                    <div class="stat-title">HTTP Methods</div>
                    <div class="stat-value" data-target="{len(self.method_success)}">0</div>
                </div>
            </div>

            <div class="section card">
                <h2>Scan Information</h2>
                <div class="terminal-section">
                    <div class="terminal-header">FuzzStorm > ./scan_config.sh</div>
                    <div class="terminal-content">
                        <pre><code> Target URL:       {self.target_url}
    Wordlist:         {self.wordlist}
    Extensions:       {', '.join(self.extensions) if self.extensions else 'None'}
    Threads Used:     {self.threads}
    Delay:            {self.delay} seconds
    HTTP Method Test: {'Enabled' if self.test_methods else 'Disabled'}
    Security Analysis: {'Enabled' if self.security_analysis else 'Disabled'}
    Proxy:            {self.proxy if self.proxy else 'None'}</div>
                </div>
            </div>

            <div class="section card">
                <h2>Results Summary</h2>
                <div class="chart-container">
                    <canvas id="statusChart"></canvas>
                </div>

                <h3>HTTP Status Codes</h3>
                <table id="statusTable">
                    <tr>
                        <th>Status Code</th>
                        <th>Count</th>
                        <th>Percentage</th>
                    </tr>
    """)

                # Count results by status code
                status_counts = {}
                for url, info in self.responses.items():
                    status = info["status"]
                    if status not in status_counts:
                        status_counts[status] = 0
                    status_counts[status] += 1

                # Calculate total for percentages
                total_responses = sum(status_counts.values())

                # Write status code table
                for status, count in sorted(status_counts.items()):
                    percentage = (count / total_responses) * 100 if total_responses > 0 else 0
                    status_class = f"code-{status}" if status in [200, 300, 400, 403, 404, 500] else ""
                    badge_class = ""

                    if 200 <= status < 300:
                        badge_class = "badge-success"
                    elif 300 <= status < 400:
                        badge_class = "badge-info"
                    elif 400 <= status < 500:
                        badge_class = "badge-warning"
                    elif 500 <= status < 600:
                        badge_class = "badge-danger"

                    f.write(f"""                <tr>
                        <td><span class="badge {badge_class}">{status}</span></td>
                        <td class="{status_class}">{count}</td>
                        <td>{percentage:.1f}%</td>
                    </tr>
    """)

                f.write("""            </table>
            </div>

            <div class="section card">
                <h2>Discovered URLs</h2>
                <p>Total resources found: <strong>{valid_resources}</strong> (excluding 404s and soft 404s)</p>
                <div class="url-list">
                    <table>
                        <tr>
                            <th>URL</th>
                            <th>Status</th>
                            <th>Size</th>
                        </tr>
    """.format(valid_resources=len(self.discovered_urls) - len(self.soft_404s) - len(self.not_found_urls)))

                # Group URLs by status code
                urls_by_status = {}
                for url in sorted(self.discovered_urls):
                    if url in self.responses:
                        status = self.responses[url]["status"]
                        if status not in urls_by_status:
                            urls_by_status[status] = []
                        urls_by_status[status].append(url)
                    else:
                        # For URLs that have no response information
                        if "N/A" not in urls_by_status:
                            urls_by_status["N/A"] = []
                        urls_by_status["N/A"].append(url)

                # Write discovered URLs grouped by status code
                for status, urls in sorted(urls_by_status.items()):
                    # Determine CSS class based on status code
                    status_class = ""
                    badge_class = ""

                    if status == "N/A":
                        badge_class = ""
                    elif 200 <= status < 300:
                        status_class = "code-200"
                        badge_class = "badge-success"
                    elif 300 <= status < 400:
                        status_class = "code-300"
                        badge_class = "badge-info"
                    elif 400 <= status < 500:
                        if status == 403:
                            status_class = "code-403"
                        elif status == 404:
                            status_class = "code-404"
                        badge_class = "badge-warning"
                    elif 500 <= status < 600:
                        status_class = "code-500"
                        badge_class = "badge-danger"

                    for url in urls:
                        if url in self.responses:
                            content_length = self.responses[url]["content_length"]
                            status_display = status
                            current_badge_class = badge_class

                            # Check if it is a soft 404 (even if status is 200)
                            if status == 200 and hasattr(self, 'soft_404s') and url in self.soft_404s:
                                status_display = "Soft 404"
                                current_badge_class = "badge-warning"  # Use same style as warnings
                            else:
                                # For URLs with status 200 that are NOT soft 404, ensure they use badge-success
                                if status == 200:
                                    current_badge_class = "badge-success"
                        else:
                            content_length = "N/A"
                            status_display = "N/A"
                            current_badge_class = ""

                        f.write(f"""                    <tr>
                            <td><a href="{url}" target="_blank" class="url-link">{url}</a></td>
                            <td><span class="badge {current_badge_class}">{status_display}</span></td>
                            <td>{content_length}</td>
                        </tr>
    """)

                f.write("""                </table>
                </div>
            </div>
    """)

                # Write subdomains section if any
                if self.discovered_subdomains:
                    f.write("""        <div class="section">
                <h2>Discovered Subdomains</h2>
                <table>
                    <tr>
                        <th>Subdomain</th>
                        <th>IP</th>
                        <th>HTTP Status</th>
                        <th>Size</th>
                    </tr>
    """)

                    for subdomain, ip, status, content_length in sorted(self.discovered_subdomains):
                        status_class = ""
                        badge_class = ""

                        if status:
                            if 200 <= status < 300:
                                status_class = "code-200"
                                badge_class = "badge-success"
                            elif 300 <= status < 400:
                                status_class = "code-300"
                                badge_class = "badge-info"
                            elif 400 <= status < 500:
                                status_class = "code-400"
                                badge_class = "badge-warning"
                            elif 500 <= status < 600:
                                status_class = "code-500"
                                badge_class = "badge-danger"

                        status_str = f"HTTP {status}" if status else "No response"
                        content_str = f"{content_length} bytes" if content_length else "-"

                        f.write(f"""                <tr>
                        <td><strong>{subdomain}</strong></td>
                        <td>{ip}</td>
                        <td><span class="badge {badge_class}">{status_str}</span></td>
                        <td>{content_str}</td>
                    </tr>
    """)

                    f.write("""            </table>
            </div>
    """)

                # Write alternative HTTP methods section if any
                if self.method_success:
                    f.write("""        </div>

            <div class="section card">
                <h2>Alternative HTTP Methods</h2>
    """)

                    for url, methods in self.method_success.items():
                        f.write(f"""            <button class="collapsible">{url}</button>
                <div class="content">
                    <table>
                        <tr>
                            <th>Method</th>
                            <th>Data Type</th>
                            <th>Status</th>
                            <th>Size</th>
                        </tr>
    """)

                        for method, status, content_length, content_type in methods:
                            status_class = ""
                            badge_class = ""

                            if 200 <= status < 300:
                                status_class = "code-200"
                                badge_class = "badge-success"
                            elif 300 <= status < 400:
                                status_class = "code-300"
                                badge_class = "badge-info"
                            elif 400 <= status < 500:
                                status_class = "code-400"
                                badge_class = "badge-warning"
                            elif 500 <= status < 600:
                                status_class = "code-500"
                                badge_class = "badge-danger"

                            content_type_str = content_type if content_type else "-"

                            f.write(f"""                    <tr>
                            <td><code>{method}</code></td>
                            <td>{content_type_str}</td>
                            <td><span class="badge {badge_class}">{status}</span></td>
                            <td>{content_length} bytes</td>
                        </tr>
    """)

                        f.write("""                </table>
                </div>
    """)

                    f.write("""        </div>
    """)

                # Write security analysis section if enabled
                if self.security_analysis and hasattr(self, 'security_analyzer'):
                    findings = self.security_analyzer.generate_report()
                    if findings:
                        f.write("""        </div>

            <div class="section card">
                <h2>Detected Security Issues</h2>
    """)

                        for url, issues in findings.items():
                            f.write(f"""            <button class="collapsible">{url}</button>
                <div class="content">
    """)

                            # Display missing security headers
                            if "missing_security_headers" in issues:
                                f.write("""                <h3>Missing Security Headers</h3>
                    <div class="terminal-section">
                        <div class="terminal-header">Missing Security Headers</div>
                        <div class="terminal-content">
                            <table>
                                <tr>
                                    <th>Header</th>
                                    <th>Description</th>
                                </tr>
    """)

                                for header, description in issues["missing_security_headers"]:
                                    f.write(f"""                            <tr>
                                    <td><code>{header}</code></td>
                                    <td>{description}</td>
                                </tr>
    """)

                                f.write("""                        </table>
                        </div>
                    </div>
    """)

                            # Display possible vulnerabilities
                            if "vulnerabilities" in issues:
                                f.write("""                <h3>Possible Vulnerabilities</h3>
    """)

                                for vuln in issues["vulnerabilities"]:
                                    f.write(f"""                <div class="vulnerability">
                        <h4>{vuln['description']}</h4>
                        <p>Examples found:</p>
                        <pre><code>""")

                                    for i, match in enumerate(vuln['matches']):
                                        if i < 5:  # Limit to 5 examples
                                            f.write(f"""{match}
    """)

                                    f.write("""</code></pre>
                    </div>
    """)

                            f.write("""            </div>
    """)

                        f.write("""        </div>
    """)

                # Footer and HTML close
                f.write("""        <div class="footer">
                <p>Report generated by <strong>FuzzStorm</strong> - Advanced web fuzzing tool</p>
                <p>Created by <strong>adperem</strong> - © {0}</p>
                <p><a href="https://github.com/adperem/fuzzstorm" style="color: var(--accent-color);">FuzzStorm on GitHub</a> | <a href="https://adperem.github.io" style="color: var(--accent-color);">adperem.github.io</a></p>
            </div>
        </div>

        {1}
    </body>
    </html>""".format(datetime.datetime.now().year, javascript))

            print(f"\n[+] HTML report saved to: {filename}")
            return True

        except Exception as e:
            print(f"\n[-] Error exporting HTML report: {e}")
            return False

    def apply_filters(self, status_codes=None, lines=None, regexp=None, size=None, time=None, words=None, mode="or"):
        """
        Filters discovered URLs based on the specified criteria.

        Args:
            status_codes (str): HTTP status codes to consider (e.g., "200-299,301,302")
            lines (str): Number of lines in the response (e.g., ">10", "<100", "=50")
            regexp (str): Regular expression to search for in the response
            size (str): Response size in bytes (e.g., ">1000", "<5000")
            time (str): Response time in milliseconds to exclude (e.g., ">100", "<300")
            words (str): Number of words in the response to exclude (e.g., ">100", "<1000")
            mode (str): Filter operation mode: "and" or "or"

        Returns:
            set: Set of URLs that match the filters
        """
        filtered_urls = set()

        # Parse status codes
        accepted_status_codes = set()
        if status_codes:
            if status_codes.lower() == "all":
                # Accept all status codes
                accepted_status_codes = None
            else:
                # Process ranges (e.g., "200-299") and individual values
                for part in status_codes.split(','):
                    if '-' in part:
                        start, end = map(int, part.split('-'))
                        accepted_status_codes.update(range(start, end + 1))
                    else:
                        accepted_status_codes.add(int(part))

        # For each discovered URL, apply filters
        for url in self.discovered_urls:
            # Get response information
            if url not in self.responses:
                continue

            info = self.responses[url]
            match_results = []

            # Filter by status code
            if accepted_status_codes is None:  # "all" was specified
                match_results.append(True)
            elif status_codes and info.get("status"):
                match_results.append(info.get("status") in accepted_status_codes)

            # Filter by number of lines
            if lines and info.get("content"):
                content_str = self._get_content_as_string(info.get("content"))
                line_count = len(content_str.splitlines())
                match_results.append(self._compare_numeric(line_count, lines))

            # Filter by regular expression
            if regexp and info.get("content"):
                content_str = self._get_content_as_string(info.get("content"))
                try:
                    pattern = re.compile(regexp)
                    match_results.append(bool(pattern.search(content_str)))
                except re.error:
                    # If the regular expression is invalid, it doesn't match
                    match_results.append(False)

            # Filter by response size
            if size and info.get("content_length") is not None:
                match_results.append(self._compare_numeric(info.get("content_length"), size))

            # Filter by response time
            if time and info.get("response_time") is not None:
                match_results.append(self._compare_numeric(info.get("response_time"), time))

            # Filter by number of words
            if words and info.get("content"):
                content_str = self._get_content_as_string(info.get("content"))
                word_count = len(content_str.split())
                match_results.append(self._compare_numeric(word_count, words))

            # Apply the operation mode
            if mode.lower() == "and":
                # All filters must match
                if match_results and all(match_results):
                    filtered_urls.add(url)
            else:  # "or" is the default
                # At least one filter must match
                if match_results and any(match_results):
                    filtered_urls.add(url)

        return filtered_urls

    def _compare_numeric(self, value, comparison_str):
        """
        Compares a numeric value based on a comparison string.

        Args:
            value (int/float): The value to compare
            comparison_str (str): The comparison string (e.g., ">100", "<50", "=200")

        Returns:
            bool: True if the comparison is successful, False otherwise
        """
        if not comparison_str:
            return False

        try:
            # Extract the operator and value
            if comparison_str.startswith('>'):
                return value > int(comparison_str[1:])
            elif comparison_str.startswith('<'):
                return value < int(comparison_str[1:])
            elif comparison_str.startswith('='):
                return value == int(comparison_str[1:])
            else:
                # If no operator, assume equality
                return value == int(comparison_str)
        except (ValueError, TypeError):
            return False

    def show_banner(self):
        """Display a banner with crawler information"""
        banner = f"""
{Colors.BOLD if self.use_colors else ''}╔═══════════════════════════════════════════════════════════════════════════════════╗
{Colors.BOLD if self.use_colors else ''}║                                                                                   ║
{Colors.BOLD if self.use_colors else ''}║                                                                                   ║
{Colors.BOLD if self.use_colors else ''}║   ███████╗██╗   ██╗███████╗███████╗███████╗████████╗ ██████╗ ██████╗ ███╗   ███╗  ║
{Colors.BOLD if self.use_colors else ''}║   ██╔════╝██║   ██║╚══███╔╝╚══███╔╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗████╗ ████║  ║
{Colors.BOLD if self.use_colors else ''}║   █████╗  ██║   ██║  ███╔╝   ███╔╝ ███████╗   ██║   ██║   ██║██████╔╝██╔████╔██║  ║
{Colors.BOLD if self.use_colors else ''}║   ██╔══╝  ██║   ██║ ███╔╝   ███╔╝  ╚════██║   ██║   ██║   ██║██╔══██╗██║╚██╔╝██║  ║
{Colors.BOLD if self.use_colors else ''}║   ██║     ╚██████╔╝███████╗███████╗███████║   ██║   ╚██████╔╝██║  ██║██║ ╚═╝ ██║  ║
{Colors.BOLD if self.use_colors else ''}║   ╚═╝      ╚═════╝ ╚══════╝╚══════╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝  ║
{Colors.BOLD if self.use_colors else ''}║                                                                                   ║
{Colors.BOLD if self.use_colors else ''}╚═══════════════════════════════════════════════════════════════════════════════════╝{Colors.RESET}
        """
        info = f"""
            {Colors.YELLOW if self.use_colors else ''}Advanced Web Fuzzing Tool v1.0 - Created by adperem
            {Colors.YELLOW if self.use_colors else ''}https://adperem.github.io/                       
        """
        
        if self.use_colors:
            print(f"{Colors.CYAN}{banner}{Colors.RESET}")
            print(info)
        else:
            print(banner)
            print(info)


def detect_web_technologies(target_url, proxy=None):
    """Detects web technologies using the Wappalyzer CLI.

    The Wappalyzer CLI honors HTTP(S)_PROXY and ALL_PROXY environment variables,
    so ensure those are set when a proxy (including Tor via socks5h) is
    configured for the scan.
    """
    print(Colors.format_info("Detecting web technologies with Wappalyzer CLI..."))

    env = os.environ.copy()
    if proxy:
        env.update({
            "HTTP_PROXY": proxy,
            "HTTPS_PROXY": proxy,
            "ALL_PROXY": proxy,
        })
        print(Colors.format_info(f"Routing Wappalyzer traffic through proxy: {proxy}"))

    try:
        result = subprocess.run(
            ["wappalyzer", target_url],
            capture_output=True,
            text=True,
            check=True,
            env=env
        )
    except FileNotFoundError:
        print(
            Colors.format_error(
                "Wappalyzer CLI not found. Install it from "
                "https://github.com/gokulapap/wappalyzer-cli inside a virtual environment (python3 -m venv venv)."
            )
        )
        return
    except subprocess.CalledProcessError as exc:
        print(Colors.format_error("Wappalyzer CLI failed to analyze the target."))
        if exc.stdout:
            print(exc.stdout.strip())
        if exc.stderr:
            print(exc.stderr.strip())
        return

    output = result.stdout.strip()
    if output:
        print(Colors.format_success("Detected technologies:"))
        print(output)
    else:
        print(Colors.format_warning("Wappalyzer CLI returned no output."))

def main():
    parser = argparse.ArgumentParser(description='FuzzStorm - Advanced web fuzzing tool')
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-w', '--wordlist', required=True, help='Path to the wordlist file')
    parser.add_argument('-e', '--extensions', help='File extensions to search for (comma-separated)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('-d', '--delay', type=float, default=0,
                        help='Delay between requests in seconds (default: 0)')
    parser.add_argument('-o', '--output', help='Output file to save results')
    parser.add_argument('--format', choices=['txt', 'json', 'csv'], default='txt',
                        help='Output format: txt, json, or csv (default: txt)')
    parser.add_argument('--max-depth', type=int, default=3,
                        help='Maximum depth for recursive scanning (default: 3)')
    parser.add_argument('--no-test-methods', action='store_true', help='Disable testing of alternative HTTP methods')
    parser.add_argument('--subdomains', action='store_true', help='Enable subdomain search')
    parser.add_argument('--no-content-scan', action='store_true',
                        help='Disable content scanning for new URLs')
    parser.add_argument('--proxy',
                        help='Use proxy for requests (format: http://ip:port or socks5://ip:port)')
    parser.add_argument('--tor', action='store_true',
                        help='Route traffic through Tor (requires Tor to be installed and running)')
    parser.add_argument('--security-analysis', action='store_true',
                        help='Enable security analysis (headers, patterns, and Techackz scan)')
    parser.add_argument('--tech-detect', action='store_true',
                        help='Show detected web technologies using the Wappalyzer CLI')
    parser.add_argument('--no-report', action='store_true', help='Disable automatic report generation')
    parser.add_argument('--no-detect-soft-404', action='store_true',
                        help='Disable detection of soft 404 pages (enabled by default)')
    parser.add_argument('--soft-404-threshold', type=float, default=0.9,
                        help='Similarity threshold for soft 404 detection (0.0-1.0, default: 0.9)')
    parser.add_argument('--debug', action='store_true', help='Enable detailed debug messages')

    # Add group of options for matchers
    matcher_group = parser.add_argument_group('MATCHER OPTIONS')
    matcher_group.add_argument('-mc', '--match-code', default='200-299,301,302,307,401,403,405,500',
                               help='Match HTTP status codes, or "all" for everything. (default: 200-299,301,302,307,401,403,405,500)')
    matcher_group.add_argument('-ml', '--match-lines',
                               help='Match amount of lines in response (e.g. ">10", "<100", "=50")')
    matcher_group.add_argument('-mmode', '--match-mode', choices=['and', 'or'], default='or',
                               help='Matcher set operator. Either of: and, or (default: or)')
    matcher_group.add_argument('-mr', '--match-regexp',
                               help='Match regexp in response content')
    matcher_group.add_argument('-ms', '--match-size',
                               help='Match HTTP response size in bytes (e.g. ">1000", "<5000")')
    matcher_group.add_argument('-mt', '--match-time',
                               help='Match how many milliseconds to the first response byte. (e.g. ">100" or "<100")')
    matcher_group.add_argument('-mw', '--match-words',
                               help='Match amount of words in response (e.g. ">100", "<1000")')

    # Add group of options for filters (exclusion)
    filter_group = parser.add_argument_group('FILTER OPTIONS')
    filter_group.add_argument('-fc', '--filter-code',
                              help='Filter HTTP status codes from response. Comma separated list of codes and ranges')
    filter_group.add_argument('-fl', '--filter-lines',
                              help='Filter by amount of lines in response. Comma separated list of line counts and ranges')
    filter_group.add_argument('-fmode', '--filter-mode', choices=['and', 'or'], default='or',
                              help='Filter set operator. Either of: and, or (default: or)')
    filter_group.add_argument('-fr', '--filter-regexp',
                              help='Filter regexp')
    filter_group.add_argument('-fs', '--filter-size',
                              help='Filter HTTP response size. Comma separated list of sizes and ranges')
    filter_group.add_argument('-ft', '--filter-time',
                              help='Filter by number of milliseconds to the first response byte, either greater or less than. EG: >100 or <100')
    filter_group.add_argument('-fw', '--filter-words',
                              help='Filter by amount of words in response. Comma separated list of word counts and ranges')

    args = parser.parse_args()

    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        print("[-] Error: The URL must start with 'http://' or 'https://'")
        sys.exit(1)

    # Validate wordlist
    if not os.path.isfile(args.wordlist):
        print(f"[-] Error: The wordlist file '{args.wordlist}' does not exist or is not accessible")
        sys.exit(1)

    # Check for conflict between proxy and tor
    if args.proxy and args.tor:
        print("[-] Error: Cannot use --proxy and --tor simultaneously")
        sys.exit(1)

    # Process extensions (use provided ones, otherwise use defaults)
    extensions = args.extensions.split(',') if args.extensions else DEFAULT_EXTENSIONS

    # Verify dependencies for subdomain search
    if args.subdomains:
        try:
            import dns.resolver
        except ImportError:
            print("[-] Error: To search for subdomains, you need to install 'dnspython'")
            print("[-] Install it with: pip install dnspython")
            sys.exit(1)

    # Verify dependencies for Tor
    if args.tor:
        try:
            import socks
        except ImportError:
            print("[-] Error: To use Tor, you need to install 'PySocks'")
            print("[-] Install it with: pip install PySocks")
            sys.exit(1)

        # Route traffic through the default Tor SOCKS proxy
        args.proxy = 'socks5h://127.0.0.1:9050'
        print(Colors.format_info(f"Using Tor proxy at {args.proxy}"))

    if args.tech_detect:
        detect_web_technologies(args.url, proxy=args.proxy)

    # Create a global variable to store the FuzzStorm instance
    global fuzzer
    fuzzer = FuzzStorm(
        target_url=args.url,
        wordlist=args.wordlist,
        extensions=extensions,
        threads=args.threads,
        delay=args.delay,
        test_methods=not args.no_test_methods,
        proxy=args.proxy,
        security_analysis=args.security_analysis,
        detect_soft_404=not args.no_detect_soft_404,
        soft_404_threshold=args.soft_404_threshold,
        debug=args.debug
    )

    # Capture SIGINT signal to handle it properly
    signal.signal(signal.SIGINT, handle_keyboard_interrupt)

    discovered_urls, discovered_subdomains = fuzzer.run_all_scans(scan_subdomains=args.subdomains)

    # If content scanning was not disabled and hasn't been performed yet, execute it now
    if not args.no_content_scan and not fuzzer.content_scan_done:
        fuzzer.content_scan()

    # Apply matchers (inclusion) to results if specified
    matched_urls = None
    if any([args.match_code, args.match_lines, args.match_regexp,
            args.match_size, args.match_time, args.match_words]):
        matched_urls = fuzzer.apply_filters(
            status_codes=args.match_code,
            lines=args.match_lines,
            regexp=args.match_regexp,
            size=args.match_size,
            time=args.match_time,
            words=args.match_words,
            mode=args.match_mode
        )
        print(
            f"\n[*] Filtering results (matchers): {len(matched_urls)} URLs match the specified criteria")

    # Apply filters (exclusion) to results if specified
    filtered_urls = matched_urls  # Initialize with matcher results
    if any([args.filter_code, args.filter_lines, args.filter_regexp,
            args.filter_size, args.filter_time, args.filter_words]):
        # If matchers were applied, filter on those results; otherwise, filter on all
        base_urls = filtered_urls if filtered_urls is not None else fuzzer.discovered_urls
        # Store base URLs in the fuzzer temporarily to apply exclusion filters
        original_discovered = fuzzer.discovered_urls
        fuzzer.discovered_urls = base_urls

        filtered_urls = fuzzer.apply_exclusion_filters(
            status_codes=args.filter_code,
            lines=args.filter_lines,
            regexp=args.filter_regexp,
            size=args.filter_size,
            time=args.filter_time,
            words=args.filter_words,
            mode=args.filter_mode
        )

        # Restore original URLs
        fuzzer.discovered_urls = original_discovered

        print(f"\n[*] Applying exclusion filters: {len(filtered_urls)} URLs after applying filters")
    elif matched_urls is not None:
        # If only matchers were applied, use those results
        filtered_urls = matched_urls

    # Display summary of detected soft 404s
    if not args.no_detect_soft_404:
        soft_404_count = len(getattr(fuzzer, 'soft_404s', set()))
        real_200_count = len(getattr(fuzzer, 'real_200s', set()))

        if soft_404_count > 0 or real_200_count > 0:
            print(f"\n[*] Soft 404 detection summary:")
            print(f"    - Soft 404s detected: {soft_404_count}")
            print(f"    - Real 200 URLs: {real_200_count}")

            # If we have filtered URLs, update to exclude soft 404s
            if filtered_urls is not None:
                filtered_urls = filtered_urls - getattr(fuzzer, 'soft_404s', set())
                print(f"    - URLs after excluding soft 404s: {len(filtered_urls)}")

    # Export results
    if args.output:
        # Determine format based on file extension if not manually specified
        output_format = args.format
        if not output_format or output_format == 'txt':
            # Extract file extension
            file_ext = os.path.splitext(args.output)[1].lower().lstrip('.')
            # Use extension as format if it is one of the supported ones
            if file_ext in ['txt', 'json', 'csv']:
                output_format = file_ext
                if args.debug:
                    print(f"[DEBUG] Output format automatically detected: {output_format}")

        # If an output file was specified, use that
        fuzzer.export_results(args.output, format=output_format, filtered_urls=filtered_urls)
    elif not args.no_report:
        # If no output file was specified but reports weren't disabled,
        # automatically generate a TXT report named based on domain and timestamp
        try:
            # Extract domain from URL for use in filename
            domain = urlparse(args.url).netloc
            # Clean domain (remove port if present and invalid filename characters)
            domain = domain.split(':')[0].replace('.', '_')

            # Generate filename with timestamp
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"fuzzstorm_report_{domain}_{timestamp}.txt"

            # Create "reports" directory if it doesn't exist
            if not os.path.exists('reports'):
                os.makedirs('reports')

            # Save the report
            report_path = os.path.join('reports', output_file)
            fuzzer.export_results(report_path, format='txt', filtered_urls=filtered_urls)
            print(f"\n[+] Automatic report saved to: {report_path}")
        except Exception as e:
            print(f"\n[-] Error saving automatic report: {e}")

    # Modify fuzzer to store filtered URLs
    if filtered_urls is not None:
        fuzzer.filtered_urls = filtered_urls

    # Return the FuzzStorm instance for later use
    return fuzzer


if __name__ == "__main__":
    try:
        # Add an import needed within the functions
        import concurrent.futures

        # Run the main program and get the FuzzStorm instance
        fuzzer = main()

        # Upon completion, ask if an HTML report should be generated
        try:
            print("\nWould you like to generate a detailed HTML report? (y/n): ", end="")
            response = input().strip().lower()

            if response in ['y', 'yes']:
                print("Enter the HTML file name (or press Enter for default): ", end="")
                filename = input().strip()

                # If no name is provided, use a default one
                if not filename:
                    domain = urlparse(fuzzer.target_url).netloc
                    domain = domain.split(':')[0].replace('.', '_')
                    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                    filename = f"fuzzstorm_report_{domain}_{timestamp}.html"

                # Ensure the file has a .html extension
                if not filename.endswith('.html'):
                    filename += '.html'

                # Generate the HTML report using the fuzzer instance
                fuzzer.export_html_report(filename)
        except Exception as e:
            print(f"\n[-] Error generating HTML report: {e}")
    except KeyboardInterrupt:
        # Nothing to do here, as interruption is handled in the code
        print("\n[+] Program terminated")
