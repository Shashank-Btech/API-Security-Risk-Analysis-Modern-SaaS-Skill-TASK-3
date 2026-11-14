#!/usr/bin/env python3
"""
Input Validation Tester
========================
Tests API endpoints for input validation vulnerabilities:
- SQL Injection
- Cross-Site Scripting (XSS)
- Command Injection
- Path Traversal
- Data Type Confusion
- Oversized Payloads
- Special Characters Handling

Author: Shashank K
Date: November 2026
"""

import requests
import json
import time
from datetime import datetime
from colorama import init, Fore, Style
from tabulate import tabulate

init(autoreset=True)


class InputValidationTester:
    """Tests API input validation and sanitization."""

    def __init__(self):
        self.findings = []
        self.test_results = []

    def log(self, level, msg):
        colors = {"INFO": Fore.CYAN, "WARN": Fore.YELLOW, "CRIT": Fore.RED,
                  "PASS": Fore.GREEN, "TEST": Fore.MAGENTA}
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] {colors.get(level, Fore.WHITE)}[{level}]{Style.RESET_ALL} {msg}")

    def add_finding(self, severity, title, description, recommendation):
        self.findings.append({
            "severity": severity,
            "title": title,
            "description": description,
            "recommendation": recommendation,
        })

    # ========================================================================
    # SQL Injection Tests
    # ========================================================================
    def test_sql_injection(self):
        """Test for SQL injection vulnerabilities."""
        print(f"\n{Fore.MAGENTA}{'─' * 60}")
        print(f"  TEST 1: SQL Injection")
        print(f"{'─' * 60}\n")

        # GET parameter injection
        sqli_payloads = [
            "' OR '1'='1",
            "1 UNION SELECT * FROM users--",
            "'; DROP TABLE users;--",
            "1' AND '1'='1",
            "admin'--",
            "1 OR 1=1",
        ]

        get_endpoints = [
            ("JSONPlaceholder", "https://jsonplaceholder.typicode.com/users?id="),
            ("DummyJSON", "https://dummyjson.com/products/search?q="),
        ]

        for api_name, base_url in get_endpoints:
            self.log("TEST", f"SQL Injection on GET: {base_url}")
            for payload in sqli_payloads:
                url = f"{base_url}{payload}"
                try:
                    response = requests.get(url, timeout=10)
                    resp_text = response.text.lower()

                    # Check for SQL error messages
                    sql_errors = ["sql", "syntax error", "mysql", "postgresql",
                                  "sqlite", "oracle", "unclosed quotation",
                                  "unterminated string"]
                    error_found = any(err in resp_text for err in sql_errors)

                    # Check if payload is reflected
                    reflected = payload.lower() in resp_text

                    if error_found:
                        self.log("CRIT", f"  ⚠ SQL error exposed with payload: {payload[:30]}")
                        self.add_finding(
                            "CRITICAL",
                            f"[{api_name}] SQL Error Message Exposed",
                            f"The payload '{payload}' triggered a SQL error message in the response. "
                            f"This confirms the input reaches the database layer without sanitization "
                            f"and reveals database technology information to attackers.",
                            "Use parameterized queries (prepared statements) exclusively. "
                            "Never concatenate user input into SQL queries. "
                            "Suppress detailed error messages in production."
                        )
                    elif reflected:
                        self.log("WARN", f"  ⚠ Payload reflected: {payload[:30]}")
                        result = "REFLECTED"
                    else:
                        result = "OK"

                    self.test_results.append({
                        "test": "SQL Injection",
                        "api": api_name,
                        "payload": payload[:40],
                        "status": response.status_code,
                        "result": "SQL_ERROR" if error_found else ("REFLECTED" if reflected else "OK"),
                    })

                except Exception as e:
                    self.log("WARN", f"  Error: {e}")

        # POST body injection
        post_endpoints = [
            ("JSONPlaceholder", "https://jsonplaceholder.typicode.com/posts",
             {"title": "' OR '1'='1", "body": "test", "userId": 1}),
            ("ReqRes", "https://reqres.in/api/login",
             {"email": "admin' OR '1'='1'--", "password": "test"}),
        ]

        for api_name, url, payload in post_endpoints:
            self.log("TEST", f"SQL Injection on POST: {url}")
            try:
                response = requests.post(url, json=payload, timeout=10)
                if response.status_code in [200, 201]:
                    resp = response.json()
                    if "' OR '" in json.dumps(resp):
                        self.log("WARN", f"  ⚠ SQL payload stored in response")
                        self.add_finding(
                            "HIGH",
                            f"[{api_name}] SQL Injection Payload Accepted in POST Body",
                            f"The API accepted and stored a SQL injection payload in the request body "
                            f"without validation. While this demo API may not use a real database, "
                            f"this pattern indicates input is not sanitized before processing.",
                            "Validate and sanitize all POST/PUT body fields. Use parameterized "
                            "queries and implement input whitelisting."
                        )
            except Exception as e:
                self.log("WARN", f"  Error: {e}")

    # ========================================================================
    # XSS Tests
    # ========================================================================
    def test_xss(self):
        """Test for Cross-Site Scripting vulnerabilities."""
        print(f"\n{Fore.MAGENTA}{'─' * 60}")
        print(f"  TEST 2: Cross-Site Scripting (XSS)")
        print(f"{'─' * 60}\n")

        xss_payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '"><script>alert(document.cookie)</script>',
            "javascript:alert('XSS')",
            '<svg onload=alert("XSS")>',
            '{{7*7}}',  # Template injection
        ]

        endpoints = [
            ("JSONPlaceholder", "https://jsonplaceholder.typicode.com/posts",
             "POST", lambda p: {"title": p, "body": "test", "userId": 1}),
            ("DummyJSON", "https://dummyjson.com/products/search",
             "GET", lambda p: None),
        ]

        for api_name, url, method, make_body in endpoints:
            self.log("TEST", f"XSS testing: {url}")
            for payload in xss_payloads:
                try:
                    if method == "POST":
                        response = requests.post(url, json=make_body(payload), timeout=10)
                    else:
                        response = requests.get(f"{url}?q={payload}", timeout=10)

                    resp_text = response.text

                    # Check if XSS payload is reflected without encoding
                    if payload in resp_text:
                        self.log("CRIT", f"  ⚠ XSS payload reflected unencoded: {payload[:40]}")
                        self.add_finding(
                            "HIGH",
                            f"[{api_name}] Reflected XSS — Unencoded Script in Response",
                            f"The XSS payload '{payload[:40]}' is reflected in the API response "
                            f"without HTML encoding. If this response is rendered in a browser, "
                            f"the injected script will execute, potentially stealing session "
                            f"cookies, redirecting users, or performing actions on their behalf.",
                            "HTML-encode all output: replace <, >, \", ', & with entities. "
                            "Set Content-Type: application/json (not text/html). "
                            "Implement Content-Security-Policy header."
                        )

                    self.test_results.append({
                        "test": "XSS",
                        "api": api_name,
                        "payload": payload[:40],
                        "status": response.status_code,
                        "result": "REFLECTED" if payload in resp_text else "OK",
                    })

                except Exception as e:
                    self.log("WARN", f"  Error: {e}")

    # ========================================================================
    # Data Type & Boundary Tests
    # ========================================================================
    def test_data_types(self):
        """Test data type validation and boundary conditions."""
        print(f"\n{Fore.MAGENTA}{'─' * 60}")
        print(f"  TEST 3: Data Type & Boundary Validation")
        print(f"{'─' * 60}\n")

        test_cases = [
            {
                "name": "Negative ID",
                "url": "https://jsonplaceholder.typicode.com/users/-1",
                "method": "GET",
                "expected": [400, 404],
            },
            {
                "name": "Zero ID",
                "url": "https://jsonplaceholder.typicode.com/users/0",
                "method": "GET",
                "expected": [400, 404],
            },
            {
                "name": "Very Large ID",
                "url": "https://jsonplaceholder.typicode.com/users/99999999",
                "method": "GET",
                "expected": [400, 404],
            },
            {
                "name": "String as ID",
                "url": "https://jsonplaceholder.typicode.com/users/abc",
                "method": "GET",
                "expected": [400, 404],
            },
            {
                "name": "Special Chars in ID",
                "url": "https://jsonplaceholder.typicode.com/users/!@%23$",
                "method": "GET",
                "expected": [400, 404],
            },
            {
                "name": "Float as ID",
                "url": "https://dummyjson.com/products/1.5",
                "method": "GET",
                "expected": [400, 404],
            },
        ]

        for test in test_cases:
            self.log("TEST", f"{test['name']}: {test['url']}")
            try:
                response = requests.get(test["url"], timeout=10)
                status = response.status_code

                if status == 200:
                    self.log("WARN", f"  ⚠ Accepted invalid input (HTTP 200) — expected {test['expected']}")
                    self.test_results.append({
                        "test": "Data Type",
                        "api": "Multiple",
                        "payload": test["name"],
                        "status": status,
                        "result": "ACCEPTED (unexpected)",
                    })
                elif status in test["expected"]:
                    self.log("PASS", f"  ✓ Properly rejected (HTTP {status})")
                    self.test_results.append({
                        "test": "Data Type",
                        "api": "Multiple",
                        "payload": test["name"],
                        "status": status,
                        "result": "OK",
                    })
                else:
                    self.log("INFO", f"  ? HTTP {status}")

            except Exception as e:
                self.log("WARN", f"  Error: {e}")

        # Test oversized POST payload
        self.log("TEST", "Oversized payload test")
        try:
            big_payload = {"title": "A" * 100000, "body": "B" * 100000, "userId": 1}
            response = requests.post(
                "https://jsonplaceholder.typicode.com/posts",
                json=big_payload, timeout=15
            )
            if response.status_code in [200, 201]:
                self.log("WARN", "  ⚠ Oversized payload (200KB+) accepted")
                self.add_finding(
                    "MEDIUM",
                    "Oversized Payload Accepted",
                    "The API accepted a POST request with 200KB+ payload without size "
                    "restrictions. This enables:\n"
                    "• Denial of Service through large payload attacks\n"
                    "• Storage exhaustion\n"
                    "• Memory exhaustion on the server",
                    "Implement request body size limits (e.g., 1MB max). "
                    "Validate field lengths against expected maximums. "
                    "Use streaming parsers for large payloads."
                )
            else:
                self.log("PASS", f"  ✓ Oversized payload rejected (HTTP {response.status_code})")
        except Exception as e:
            self.log("WARN", f"  Error: {e}")

    # ========================================================================
    # Command Injection Tests
    # ========================================================================
    def test_command_injection(self):
        """Test for command injection vulnerabilities."""
        print(f"\n{Fore.MAGENTA}{'─' * 60}")
        print(f"  TEST 4: Command Injection")
        print(f"{'─' * 60}\n")

        cmd_payloads = [
            "; ls -la",
            "| cat /etc/passwd",
            "$(whoami)",
            "`id`",
            "&& echo vulnerable",
        ]

        for payload in cmd_payloads:
            self.log("TEST", f"Command injection: {payload}")
            try:
                response = requests.get(
                    f"https://httpbin.org/get?cmd={payload}",
                    timeout=10
                )
                # HTTPBin reflects parameters — check if it's processed
                if response.status_code == 200:
                    self.test_results.append({
                        "test": "Command Injection",
                        "api": "HTTPBin",
                        "payload": payload,
                        "status": 200,
                        "result": "REFLECTED (in params)",
                    })
            except Exception as e:
                self.log("WARN", f"  Error: {e}")

    # ========================================================================
    # Run All Tests
    # ========================================================================
    def run_all(self):
        """Execute all input validation tests."""
        print(f"""
{Fore.CYAN}
    ╔══════════════════════════════════════════════════════════╗
    ║         📝 INPUT VALIDATION TESTER                       ║
    ║                                                          ║
    ║  Tests: SQLi, XSS, Cmd Injection, Data Types            ║
    ║  Author: Shashank K                                      ║
    ╚══════════════════════════════════════════════════════════╝
{Style.RESET_ALL}""")

        start = datetime.now()

        self.test_sql_injection()
        self.test_xss()
        self.test_data_types()
        self.test_command_injection()

        elapsed = (datetime.now() - start).total_seconds()

        # Print results table
        print(f"\n{'=' * 60}")
        print(f"{Fore.CYAN}  📝 INPUT VALIDATION TEST SUMMARY")
        print(f"{'=' * 60}\n")

        table_data = [[r["test"], r["api"], r["payload"][:30], r["status"], r["result"]]
                      for r in self.test_results]
        print(tabulate(table_data,
                        headers=["Test", "API", "Payload", "Status", "Result"],
                        tablefmt="grid"))

        print(f"\n  Duration: {elapsed:.1f}s | Findings: {len(self.findings)}")

        # Save results
        with open("evidence/input_validation_results.json", "w") as f:
            json.dump({"findings": self.findings, "test_results": self.test_results}, f, indent=2)
        self.log("PASS", "Results saved to evidence/input_validation_results.json")


if __name__ == "__main__":
    tester = InputValidationTester()
    tester.run_all()

