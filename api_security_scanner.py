#!/usr/bin/env python3
"""
API Security Scanner - Main Orchestrator
=========================================
Comprehensive API security testing tool that checks for common vulnerabilities
including authentication issues, authorization flaws, rate-limiting gaps,
input validation problems, and insecure HTTP headers.

Author: Shashank K
Date: November 2026
Purpose: API Security Risk Analysis Project

DISCLAIMER: For educational and authorized testing only.
"""

import requests
import json
import time
import sys
from datetime import datetime
from colorama import init, Fore, Style
from tabulate import tabulate

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# ============================================================================
# CONFIGURATION
# ============================================================================

TARGET_APIS = {
    "JSONPlaceholder": {
        "base_url": "https://jsonplaceholder.typicode.com",
        "description": "Free REST API for testing (no authentication)",
        "endpoints": [
            {"method": "GET", "path": "/users", "description": "List all users"},
            {"method": "GET", "path": "/users/1", "description": "Get single user"},
            {"method": "GET", "path": "/posts", "description": "List all posts"},
            {"method": "POST", "path": "/posts", "description": "Create a post"},
            {"method": "PUT", "path": "/posts/1", "description": "Update a post"},
            {"method": "DELETE", "path": "/posts/1", "description": "Delete a post"},
            {"method": "GET", "path": "/users/1/todos", "description": "User's todos"},
        ]
    },
    "ReqRes": {
        "base_url": "https://reqres.in",
        "description": "REST API with token-based auth simulation",
        "endpoints": [
            {"method": "GET", "path": "/api/users", "description": "List users"},
            {"method": "GET", "path": "/api/users/2", "description": "Single user"},
            {"method": "POST", "path": "/api/register", "description": "Register user"},
            {"method": "POST", "path": "/api/login", "description": "Login user"},
            {"method": "DELETE", "path": "/api/users/2", "description": "Delete user"},
            {"method": "GET", "path": "/api/unknown", "description": "List resources"},
        ]
    },
    "HTTPBin": {
        "base_url": "https://httpbin.org",
        "description": "HTTP request & response inspection service",
        "endpoints": [
            {"method": "GET", "path": "/get", "description": "GET request details"},
            {"method": "GET", "path": "/headers", "description": "Request headers"},
            {"method": "GET", "path": "/ip", "description": "Origin IP address"},
            {"method": "GET", "path": "/response-headers?X-Test=true", "description": "Custom response headers"},
            {"method": "POST", "path": "/post", "description": "POST request details"},
        ]
    },
    "DummyJSON": {
        "base_url": "https://dummyjson.com",
        "description": "REST API with auth, products, and users",
        "endpoints": [
            {"method": "GET", "path": "/products", "description": "List products"},
            {"method": "GET", "path": "/products/1", "description": "Single product"},
            {"method": "GET", "path": "/users", "description": "List users"},
            {"method": "GET", "path": "/users/1", "description": "Single user details"},
            {"method": "POST", "path": "/auth/login", "description": "Authentication login"},
            {"method": "GET", "path": "/auth/me", "description": "Get current auth user"},
            {"method": "GET", "path": "/carts", "description": "List carts"},
        ]
    },
    "REST Countries": {
        "base_url": "https://restcountries.com",
        "description": "Public API for country data",
        "endpoints": [
            {"method": "GET", "path": "/v3.1/all", "description": "All countries"},
            {"method": "GET", "path": "/v3.1/name/india", "description": "Search by name"},
            {"method": "GET", "path": "/v3.1/alpha/IN", "description": "Search by code"},
        ]
    }
}

# Security headers to check
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cache-Control",
    "Access-Control-Allow-Origin",
    "Access-Control-Allow-Methods",
    "Access-Control-Allow-Headers",
]

# ============================================================================
# SCANNER CLASS
# ============================================================================

class APISecurityScanner:
    """Main API Security Scanner that orchestrates all security tests."""

    def __init__(self):
        self.findings = []
        self.scan_start = None
        self.scan_end = None
        self.total_requests = 0
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "API-Security-Scanner/1.0 (Educational)",
            "Accept": "application/json",
        })

    def log(self, level, message):
        """Print colored log messages."""
        colors = {
            "INFO": Fore.CYAN,
            "WARN": Fore.YELLOW,
            "CRIT": Fore.RED,
            "PASS": Fore.GREEN,
            "SCAN": Fore.MAGENTA,
        }
        color = colors.get(level, Fore.WHITE)
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{Fore.WHITE}[{timestamp}] {color}[{level}]{Style.RESET_ALL} {message}")

    def add_finding(self, api_name, endpoint, severity, category, title, description, recommendation):
        """Record a security finding."""
        self.findings.append({
            "api": api_name,
            "endpoint": endpoint,
            "severity": severity,
            "category": category,
            "title": title,
            "description": description,
            "recommendation": recommendation,
            "timestamp": datetime.now().isoformat(),
        })

    def make_request(self, method, url, **kwargs):
        """Make an HTTP request with error handling."""
        self.total_requests += 1
        try:
            kwargs.setdefault("timeout", 15)
            response = self.session.request(method, url, **kwargs)
            return response
        except requests.exceptions.Timeout:
            self.log("WARN", f"Timeout: {method} {url}")
            return None
        except requests.exceptions.ConnectionError:
            self.log("WARN", f"Connection failed: {method} {url}")
            return None
        except Exception as e:
            self.log("WARN", f"Error: {method} {url} -> {e}")
            return None

    # ========================================================================
    # TEST 1: Security Headers Analysis
    # ========================================================================
    def test_security_headers(self, api_name, base_url, endpoint):
        """Check for missing or misconfigured security headers."""
        url = f"{base_url}{endpoint['path']}"
        self.log("SCAN", f"Testing security headers: {url}")

        response = self.make_request(endpoint["method"], url)
        if not response:
            return

        missing_headers = []
        present_headers = []
        misconfigured = []

        for header in SECURITY_HEADERS:
            value = response.headers.get(header)
            if value:
                present_headers.append((header, value))
                # Check for misconfigured CORS
                if header == "Access-Control-Allow-Origin" and value == "*":
                    misconfigured.append(header)
                    self.add_finding(
                        api_name, endpoint["path"], "HIGH", "Security Headers",
                        f"Wildcard CORS Origin ({header}: *)",
                        f"The endpoint returns 'Access-Control-Allow-Origin: *' which allows any website to make cross-origin requests. An attacker's malicious website could read responses from this API, potentially exposing sensitive data.",
                        "Restrict CORS to specific trusted origins instead of using wildcard (*). Example: 'Access-Control-Allow-Origin: https://yourdomain.com'"
                    )
            else:
                missing_headers.append(header)

        # Report critical missing headers
        critical_missing = [h for h in missing_headers if h in [
            "Strict-Transport-Security", "Content-Security-Policy",
            "X-Content-Type-Options", "X-Frame-Options"
        ]]

        if critical_missing:
            self.add_finding(
                api_name, endpoint["path"], "MEDIUM", "Security Headers",
                f"Missing Security Headers ({len(critical_missing)} critical)",
                f"The following critical security headers are missing: {', '.join(critical_missing)}. "
                "Without these headers, the API is vulnerable to clickjacking, MIME-type sniffing attacks, "
                "and man-in-the-middle attacks.",
                "Implement the following headers:\n"
                "- Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
                "- Content-Security-Policy: default-src 'self'\n"
                "- X-Content-Type-Options: nosniff\n"
                "- X-Frame-Options: DENY"
            )

        self.log("INFO", f"  Headers present: {len(present_headers)}, missing: {len(missing_headers)}")

    # ========================================================================
    # TEST 2: Authentication Testing
    # ========================================================================
    def test_authentication(self, api_name, base_url, endpoint):
        """Test for authentication and authorization vulnerabilities."""
        url = f"{base_url}{endpoint['path']}"
        self.log("SCAN", f"Testing authentication: {url}")

        # Test 1: Access without authentication
        response = self.make_request(endpoint["method"], url)
        if not response:
            return

        if response.status_code == 200:
            # Check if this returns sensitive data without auth
            try:
                data = response.json()
                sensitive_fields = ["email", "password", "phone", "address",
                                   "ssn", "credit_card", "token", "secret",
                                   "api_key", "creditCard", "ssn", "birthDate"]

                exposed_fields = []
                data_to_check = data if isinstance(data, list) else [data]

                # Handle paginated responses
                if isinstance(data, dict):
                    for key in ["data", "users", "results", "items"]:
                        if key in data and isinstance(data[key], list):
                            data_to_check = data[key]
                            break

                for item in data_to_check[:5]:  # Check first 5 records
                    if isinstance(item, dict):
                        for field in sensitive_fields:
                            if field in item or any(field.lower() in k.lower() for k in item.keys()):
                                matching_keys = [k for k in item.keys() if field.lower() in k.lower()]
                                exposed_fields.extend(matching_keys)

                exposed_fields = list(set(exposed_fields))
                if exposed_fields:
                    self.add_finding(
                        api_name, endpoint["path"], "HIGH", "Data Exposure",
                        f"Sensitive Data Exposed Without Authentication",
                        f"The endpoint exposes sensitive user data ({', '.join(exposed_fields)}) "
                        f"without requiring any authentication. Anyone with the URL can access "
                        f"personal information like email addresses, phone numbers, or addresses. "
                        f"This is a significant privacy and compliance risk (GDPR, CCPA).",
                        "Implement authentication (e.g., JWT, OAuth 2.0) on all endpoints "
                        "that return personal or sensitive data. Apply the principle of least "
                        "privilege — only return data the authenticated user is authorized to see."
                    )
                    self.log("CRIT", f"  ⚠ Sensitive fields exposed: {', '.join(exposed_fields)}")

            except (json.JSONDecodeError, ValueError):
                pass

        # Test 2: Try accessing with invalid/empty auth tokens
        headers_to_test = [
            {"Authorization": ""},
            {"Authorization": "Bearer invalid_token_12345"},
            {"Authorization": "Bearer "},
            {"X-API-Key": "invalid_key"},
        ]

        for test_headers in headers_to_test:
            response = self.make_request(endpoint["method"], url, headers=test_headers)
            if response and response.status_code == 200:
                header_name = list(test_headers.keys())[0]
                header_value = list(test_headers.values())[0] or "(empty)"
                self.add_finding(
                    api_name, endpoint["path"], "HIGH", "Authentication",
                    f"API Accepts Invalid Authentication Token",
                    f"The endpoint accepts requests with invalid/empty authentication "
                    f"header '{header_name}: {header_value}'. This indicates either no "
                    f"authentication is enforced, or the token validation is broken. "
                    f"An attacker can bypass authentication entirely.",
                    "Implement proper token validation on every request. Reject requests "
                    "with missing, empty, expired, or malformed tokens with HTTP 401. "
                    "Use a well-tested authentication library."
                )
                break  # One finding is enough

    # ========================================================================
    # TEST 3: Authorization Testing (IDOR / Broken Access Control)
    # ========================================================================
    def test_authorization(self, api_name, base_url, endpoint):
        """Test for Insecure Direct Object Reference (IDOR) and broken access control."""
        url = f"{base_url}{endpoint['path']}"
        self.log("SCAN", f"Testing authorization (IDOR): {url}")

        # Test sequential ID enumeration
        if "/1" in endpoint["path"] or "/2" in endpoint["path"]:
            base_path = endpoint["path"].rsplit("/", 1)[0]
            accessible_ids = []

            for test_id in range(1, 6):
                test_url = f"{base_url}{base_path}/{test_id}"
                response = self.make_request("GET", test_url)
                if response and response.status_code == 200:
                    accessible_ids.append(test_id)

            if len(accessible_ids) > 1:
                self.add_finding(
                    api_name, endpoint["path"], "MEDIUM", "Authorization (IDOR)",
                    f"Sequential ID Enumeration Possible",
                    f"The endpoint uses predictable sequential IDs (tested IDs: {accessible_ids}). "
                    f"An attacker can enumerate all records by incrementing the ID value. "
                    f"Combined with missing authentication, this allows complete data extraction "
                    f"(scraping all user profiles, orders, etc.).",
                    "Use UUIDs or non-sequential random identifiers instead of auto-increment IDs. "
                    "Implement proper authorization checks to ensure users can only access their own data. "
                    "Add rate limiting to prevent mass enumeration."
                )

    # ========================================================================
    # TEST 4: Rate Limiting
    # ========================================================================
    def test_rate_limiting(self, api_name, base_url, endpoint):
        """Test if the API enforces rate limiting."""
        url = f"{base_url}{endpoint['path']}"
        self.log("SCAN", f"Testing rate limiting: {url}")

        # Send a burst of requests
        results = []
        burst_count = 20
        start_time = time.time()

        for i in range(burst_count):
            response = self.make_request(endpoint["method"], url)
            if response:
                results.append(response.status_code)
            time.sleep(0.05)  # Small delay to be respectful

        elapsed = time.time() - start_time

        # Check for rate limiting indicators
        rate_limited = any(code == 429 for code in results)
        all_success = all(code == 200 for code in results)

        # Check for rate limit headers
        if results:
            last_response = self.make_request(endpoint["method"], url)
            if last_response:
                rate_headers = {
                    "X-RateLimit-Limit": last_response.headers.get("X-RateLimit-Limit"),
                    "X-RateLimit-Remaining": last_response.headers.get("X-RateLimit-Remaining"),
                    "X-RateLimit-Reset": last_response.headers.get("X-RateLimit-Reset"),
                    "Retry-After": last_response.headers.get("Retry-After"),
                }
                has_rate_headers = any(v is not None for v in rate_headers.values())
            else:
                has_rate_headers = False

        if all_success and not rate_limited and not has_rate_headers:
            self.add_finding(
                api_name, endpoint["path"], "MEDIUM", "Rate Limiting",
                f"No Rate Limiting Detected",
                f"Sent {burst_count} rapid requests in {elapsed:.1f}s — all returned HTTP 200 "
                f"with no rate limit headers. Without rate limiting, the API is vulnerable to:\n"
                f"• Brute-force attacks on login endpoints\n"
                f"• Denial of Service (DoS) attacks\n"
                f"• Credential stuffing attacks\n"
                f"• Data scraping/harvesting",
                "Implement rate limiting using one of these approaches:\n"
                "- Token bucket or sliding window algorithms\n"
                "- Return HTTP 429 (Too Many Requests) when limits are exceeded\n"
                "- Include rate limit headers (X-RateLimit-Limit, X-RateLimit-Remaining)\n"
                "- Consider different limits for authenticated vs. unauthenticated users\n"
                "- Use API gateways (AWS API Gateway, Kong, etc.) for centralized rate limiting"
            )
            self.log("WARN", f"  ⚠ No rate limiting: {burst_count} requests in {elapsed:.1f}s, all HTTP 200")
        elif rate_limited:
            self.log("PASS", f"  ✓ Rate limiting active (HTTP 429 received)")

    # ========================================================================
    # TEST 5: Input Validation
    # ========================================================================
    def test_input_validation(self, api_name, base_url, endpoint):
        """Test input validation and injection resistance."""
        url = f"{base_url}{endpoint['path']}"
        self.log("SCAN", f"Testing input validation: {url}")

        if endpoint["method"] not in ["POST", "PUT", "PATCH"]:
            # Test query parameter injection on GET endpoints
            injection_payloads = [
                ("SQL Injection", "?id=1' OR '1'='1"),
                ("XSS Payload", "?q=<script>alert('xss')</script>"),
                ("Path Traversal", "/../../../etc/passwd"),
                ("Command Injection", "?cmd=;ls -la"),
                ("Oversized Input", f"?q={'A' * 5000}"),
            ]

            for attack_name, payload in injection_payloads:
                test_url = f"{url}{payload}"
                response = self.make_request("GET", test_url)
                if response:
                    # Check if the payload is reflected in the response
                    if payload.replace("?q=", "").replace("?id=", "").replace("?cmd=", "") in response.text:
                        self.add_finding(
                            api_name, endpoint["path"], "HIGH", "Input Validation",
                            f"Input Reflected in Response ({attack_name})",
                            f"The payload '{payload[:50]}...' is reflected back in the API response "
                            f"without sanitization. This can lead to Cross-Site Scripting (XSS), "
                            f"SQL Injection, or other injection attacks depending on how the response "
                            f"is processed by client applications.",
                            "Implement input validation and output encoding:\n"
                            "- Validate all input against expected patterns (whitelist approach)\n"
                            "- Use parameterized queries for database operations\n"
                            "- HTML-encode output to prevent XSS\n"
                            "- Set Content-Type headers correctly\n"
                            "- Implement request size limits"
                        )
                        self.log("CRIT", f"  ⚠ {attack_name} payload reflected in response!")
                        break
        else:
            # Test POST/PUT endpoints with malicious payloads
            test_payloads = [
                {
                    "name": "SQL Injection in Body",
                    "data": {"username": "admin' OR '1'='1'--", "password": "test"},
                },
                {
                    "name": "XSS in Body",
                    "data": {"title": "<script>alert('xss')</script>", "body": "test"},
                },
                {
                    "name": "Empty Required Fields",
                    "data": {"username": "", "password": ""},
                },
                {
                    "name": "Wrong Data Types",
                    "data": {"userId": "not_a_number", "id": ["array_instead_of_int"]},
                },
                {
                    "name": "Oversized Payload",
                    "data": {"title": "A" * 10000, "body": "B" * 10000},
                },
            ]

            for payload_info in test_payloads:
                response = self.make_request(
                    endpoint["method"], url,
                    json=payload_info["data"],
                    headers={"Content-Type": "application/json"}
                )
                if response:
                    # API should reject malicious input (4xx) but if it accepts (2xx)...
                    if response.status_code in [200, 201]:
                        # Check if SQL/XSS payloads are stored as-is
                        try:
                            resp_data = response.json()
                            resp_text = json.dumps(resp_data)
                            if "<script>" in resp_text or "OR '1'='1'" in resp_text:
                                self.add_finding(
                                    api_name, endpoint["path"], "HIGH", "Input Validation",
                                    f"Malicious Input Accepted & Stored ({payload_info['name']})",
                                    f"The API accepted and stored potentially malicious input without "
                                    f"validation or sanitization. The payload '{payload_info['name']}' "
                                    f"was accepted with HTTP {response.status_code}. This could lead to "
                                    f"stored XSS attacks, SQL injection, or data corruption.",
                                    "Implement server-side input validation:\n"
                                    "- Reject requests with unexpected special characters\n"
                                    "- Validate data types, lengths, and formats\n"
                                    "- Sanitize all input before storage\n"
                                    "- Use parameterized queries (never string concatenation)\n"
                                    "- Return HTTP 400/422 for invalid input with clear error messages"
                                )
                                self.log("CRIT", f"  ⚠ {payload_info['name']} was accepted and stored!")
                                break
                        except (json.JSONDecodeError, ValueError):
                            pass

    # ========================================================================
    # TEST 6: Information Disclosure
    # ========================================================================
    def test_information_disclosure(self, api_name, base_url, endpoint):
        """Check for information disclosure in responses and error messages."""
        url = f"{base_url}{endpoint['path']}"
        self.log("SCAN", f"Testing information disclosure: {url}")

        response = self.make_request(endpoint["method"], url)
        if not response:
            return

        # Check server header disclosure
        server = response.headers.get("Server")
        x_powered = response.headers.get("X-Powered-By")

        if server and any(v in server.lower() for v in ["apache", "nginx", "iis", "express"]):
            self.add_finding(
                api_name, endpoint["path"], "LOW", "Information Disclosure",
                f"Server Technology Disclosed (Server: {server})",
                f"The 'Server' header reveals the web server technology: '{server}'. "
                f"Attackers can use this information to search for known vulnerabilities "
                f"specific to this server version and craft targeted attacks.",
                "Remove or generalize the Server header. In production:\n"
                "- Nginx: Add 'server_tokens off;' to nginx.conf\n"
                "- Apache: Add 'ServerTokens Prod' and 'ServerSignature Off'\n"
                "- Express: Use helmet middleware with hidePoweredBy()"
            )

        if x_powered:
            self.add_finding(
                api_name, endpoint["path"], "LOW", "Information Disclosure",
                f"Technology Stack Disclosed (X-Powered-By: {x_powered})",
                f"The 'X-Powered-By: {x_powered}' header reveals the backend technology. "
                f"This helps attackers fingerprint the application and find version-specific exploits.",
                "Remove the X-Powered-By header entirely. In Express.js: app.disable('x-powered-by') "
                "or use the 'helmet' middleware."
            )

        # Test error handling with bad requests
        error_urls = [
            f"{base_url}/nonexistent_endpoint_xyz",
            f"{base_url}{endpoint['path']}?format=invalid",
        ]

        for error_url in error_urls:
            error_response = self.make_request("GET", error_url)
            if error_response:
                text = error_response.text.lower()
                if any(indicator in text for indicator in [
                    "stack trace", "traceback", "exception", "debug",
                    "sql", "syntax error", "internal server error",
                    "at line", "file \"", "node_modules"
                ]):
                    self.add_finding(
                        api_name, endpoint["path"], "MEDIUM", "Information Disclosure",
                        "Verbose Error Messages / Stack Traces Exposed",
                        "Error responses contain detailed technical information such as stack traces, "
                        "file paths, or SQL queries. This information helps attackers understand the "
                        "application's internal structure, technology stack, and potential attack vectors.",
                        "Implement proper error handling:\n"
                        "- Return generic error messages to clients (e.g., 'An error occurred')\n"
                        "- Log detailed errors server-side only\n"
                        "- Use different error detail levels for dev/staging/production\n"
                        "- Never expose stack traces, file paths, or SQL queries in responses"
                    )
                    break

    # ========================================================================
    # TEST 7: HTTPS/TLS
    # ========================================================================
    def test_transport_security(self, api_name, base_url, endpoint):
        """Test transport layer security (HTTPS enforcement)."""
        self.log("SCAN", f"Testing transport security: {base_url}")

        # Check if HTTP (non-HTTPS) is accepted
        if base_url.startswith("https://"):
            http_url = base_url.replace("https://", "http://") + endpoint["path"]
            try:
                response = requests.get(http_url, timeout=10, allow_redirects=False)
                if response.status_code == 200:
                    self.add_finding(
                        api_name, endpoint["path"], "HIGH", "Transport Security",
                        "API Accessible Over Unencrypted HTTP",
                        "The API responds to plain HTTP requests without redirecting to HTTPS. "
                        "Data transmitted over HTTP is visible to anyone on the network "
                        "(man-in-the-middle attacks). This exposes API keys, tokens, user "
                        "credentials, and personal data in transit.",
                        "Enforce HTTPS-only access:\n"
                        "- Redirect all HTTP requests to HTTPS (301 redirect)\n"
                        "- Add HSTS header (Strict-Transport-Security)\n"
                        "- Use TLS 1.2 or higher\n"
                        "- Disable older SSL/TLS versions"
                    )
                elif response.status_code in [301, 302, 308]:
                    location = response.headers.get("Location", "")
                    if location.startswith("https://"):
                        self.log("PASS", f"  ✓ HTTP properly redirects to HTTPS")
            except Exception:
                self.log("INFO", f"  HTTP connection refused (good - HTTPS only)")

    # ========================================================================
    # MAIN SCAN ORCHESTRATOR
    # ========================================================================
    def run_full_scan(self):
        """Execute the complete security scan."""
        self.scan_start = datetime.now()

        print("\n" + "=" * 70)
        print(f"{Fore.CYAN}{'':>10}🔐 API SECURITY RISK ANALYSIS SCANNER")
        print(f"{'':>10}{'=' * 50}")
        print(f"{'':>10}Started: {self.scan_start.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'':>10}Target APIs: {len(TARGET_APIS)}")
        print("=" * 70 + "\n")

        for api_name, api_config in TARGET_APIS.items():
            print(f"\n{Fore.MAGENTA}{'─' * 60}")
            print(f"  📡 Scanning: {api_name}")
            print(f"  🌐 Base URL: {api_config['base_url']}")
            print(f"  📝 {api_config['description']}")
            print(f"{'─' * 60}\n")

            for endpoint in api_config["endpoints"]:
                self.log("INFO", f"Testing: {endpoint['method']} {endpoint['path']} — {endpoint['description']}")

                try:
                    # Run all test categories
                    self.test_security_headers(api_name, api_config["base_url"], endpoint)
                    self.test_authentication(api_name, api_config["base_url"], endpoint)
                    self.test_authorization(api_name, api_config["base_url"], endpoint)
                    self.test_rate_limiting(api_name, api_config["base_url"], endpoint)
                    self.test_input_validation(api_name, api_config["base_url"], endpoint)
                    self.test_information_disclosure(api_name, api_config["base_url"], endpoint)
                    self.test_transport_security(api_name, api_config["base_url"], endpoint)
                except Exception as e:
                    self.log("WARN", f"Error testing endpoint: {e}")

                time.sleep(0.5)  # Be respectful to the APIs

        self.scan_end = datetime.now()
        self.print_summary()
        self.save_results()

    def print_summary(self):
        """Print the scan summary with findings table."""
        duration = (self.scan_end - self.scan_start).total_seconds()

        print(f"\n\n{'=' * 70}")
        print(f"{Fore.CYAN}{'':>10}📊 SCAN SUMMARY")
        print(f"{'=' * 70}\n")
        print(f"  Duration:         {duration:.1f} seconds")
        print(f"  Total Requests:   {self.total_requests}")
        print(f"  Findings:         {len(self.findings)}")

        # Count by severity
        severity_counts = {}
        for f in self.findings:
            severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

        severity_colors = {"CRITICAL": Fore.RED, "HIGH": Fore.RED, "MEDIUM": Fore.YELLOW, "LOW": Fore.GREEN}
        print(f"\n  Severity Breakdown:")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = severity_counts.get(sev, 0)
            color = severity_colors.get(sev, Fore.WHITE)
            bar = "█" * count + "░" * (20 - count)
            print(f"    {color}{sev:10s}{Style.RESET_ALL} [{bar}] {count}")

        # Findings table
        if self.findings:
            print(f"\n\n{'─' * 70}")
            print(f"{Fore.CYAN}  DETAILED FINDINGS:")
            print(f"{'─' * 70}\n")

            table_data = []
            for i, f in enumerate(self.findings, 1):
                sev_icon = {"CRITICAL": "🔴", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}.get(f["severity"], "⚪")
                table_data.append([
                    i,
                    sev_icon + " " + f["severity"],
                    f["api"],
                    f["category"],
                    f["title"][:50] + ("..." if len(f["title"]) > 50 else ""),
                ])

            headers = ["#", "Severity", "API", "Category", "Title"]
            print(tabulate(table_data, headers=headers, tablefmt="grid"))

        print(f"\n{'=' * 70}")
        print(f"{Fore.GREEN}  ✅ Scan Complete! Results saved to: evidence/scan_results.json")
        print(f"{'=' * 70}\n")

    def save_results(self):
        """Save scan results to JSON file."""
        results = {
            "scan_metadata": {
                "scanner": "API Security Scanner v1.0",
                "scan_start": self.scan_start.isoformat(),
                "scan_end": self.scan_end.isoformat(),
                "duration_seconds": (self.scan_end - self.scan_start).total_seconds(),
                "total_requests": self.total_requests,
                "total_findings": len(self.findings),
                "apis_tested": list(TARGET_APIS.keys()),
            },
            "severity_summary": {},
            "findings": self.findings,
        }

        # Count by severity
        for f in self.findings:
            sev = f["severity"]
            results["severity_summary"][sev] = results["severity_summary"].get(sev, 0) + 1

        output_path = "evidence/scan_results.json"
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            self.log("PASS", f"Results saved to {output_path}")
        except Exception as e:
            self.log("WARN", f"Could not save results: {e}")
            # Try current directory
            try:
                with open("scan_results.json", "w", encoding="utf-8") as f:
                    json.dump(results, f, indent=2, ensure_ascii=False)
                self.log("PASS", "Results saved to scan_results.json")
            except Exception as e2:
                self.log("WARN", f"Could not save results: {e2}")


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================
if __name__ == "__main__":
    print(f"""
{Fore.CYAN}
    ╔══════════════════════════════════════════════════════════╗
    ║         🔐 API SECURITY RISK ANALYSIS SCANNER          ║
    ║                                                          ║
    ║  Author:  Shashank K                                     ║
    ║  Version: 1.0                                            ║
    ║  Purpose: Educational API Security Testing               ║
    ║                                                          ║
    ║  ⚠  For authorized testing only!                        ║
    ╚══════════════════════════════════════════════════════════╝
{Style.RESET_ALL}""")

    scanner = APISecurityScanner()
    scanner.run_full_scan()

