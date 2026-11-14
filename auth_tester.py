#!/usr/bin/env python3
"""
Authentication & Authorization Tester
=======================================
Tests API authentication mechanisms for common vulnerabilities:
- Missing authentication on protected endpoints
- Weak token validation
- Broken access control (IDOR)
- Privilege escalation
- Session management issues

Author: Shashank K
Date: November 2026
"""

import requests
import json
import time
from datetime import datetime
from colorama import init, Fore, Style

init(autoreset=True)


class AuthTester:
    """Tests API authentication and authorization mechanisms."""

    def __init__(self):
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "AuthTester/1.0 (Educational)",
            "Accept": "application/json",
        })

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
            "timestamp": datetime.now().isoformat(),
        })

    # ========================================================================
    # Test 1: Unauthenticated Access to Sensitive Endpoints
    # ========================================================================
    def test_unauthenticated_access(self):
        """Check if sensitive endpoints are accessible without authentication."""
        print(f"\n{Fore.MAGENTA}{'─' * 60}")
        print(f"  TEST 1: Unauthenticated Access to Sensitive Data")
        print(f"{'─' * 60}\n")

        endpoints = [
            ("JSONPlaceholder", "https://jsonplaceholder.typicode.com/users",
             "User data including email, phone, address"),
            ("DummyJSON", "https://dummyjson.com/users",
             "User data with personal details"),
            ("DummyJSON", "https://dummyjson.com/carts",
             "Shopping cart data"),
            ("ReqRes", "https://reqres.in/api/users",
             "User directory"),
        ]

        for api_name, url, data_desc in endpoints:
            self.log("TEST", f"Testing unauthenticated access: {url}")
            try:
                response = self.session.get(url, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    record_count = len(data) if isinstance(data, list) else len(data.get("data", data.get("users", [])))
                    self.log("CRIT", f"  ⚠ {api_name}: {record_count} records accessible without auth")
                    self.log("INFO", f"    Data type: {data_desc}")

                    # Check for sensitive fields
                    sample = data[0] if isinstance(data, list) else (data.get("data", data.get("users", [{}]))[0] if isinstance(data.get("data", data.get("users")), list) else {})
                    sensitive = [k for k in sample.keys() if any(s in k.lower() for s in
                                ["email", "phone", "address", "password", "birth", "ssn", "ip", "card"])]
                    if sensitive:
                        self.log("CRIT", f"    Sensitive fields exposed: {', '.join(sensitive)}")
                        self.add_finding(
                            "HIGH",
                            f"[{api_name}] Sensitive Data Accessible Without Authentication",
                            f"The endpoint {url} returns {record_count} records containing sensitive "
                            f"fields ({', '.join(sensitive)}) without requiring any authentication. "
                            f"Any user or bot with the URL can access this data.",
                            "Require authentication (JWT/OAuth2) for all endpoints returning personal data. "
                            "Implement role-based access control (RBAC)."
                        )
                else:
                    self.log("PASS", f"  ✓ {api_name}: Properly returns HTTP {response.status_code}")
            except Exception as e:
                self.log("WARN", f"  Error: {e}")

    # ========================================================================
    # Test 2: Token Validation Weakness
    # ========================================================================
    def test_token_validation(self):
        """Test if APIs properly validate authentication tokens."""
        print(f"\n{Fore.MAGENTA}{'─' * 60}")
        print(f"  TEST 2: Token Validation Testing")
        print(f"{'─' * 60}\n")

        test_tokens = [
            ("Empty Bearer Token", "Bearer "),
            ("Invalid Token", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.INVALID.INVALID"),
            ("Expired Token Format", "Bearer expired_token_123"),
            ("Wrong Auth Scheme", "Basic dXNlcjpwYXNz"),
            ("No Scheme", "raw_token_value_123456"),
            ("Null Token", "Bearer null"),
            ("SQL in Token", "Bearer ' OR '1'='1"),
        ]

        protected_endpoints = [
            ("DummyJSON", "https://dummyjson.com/auth/me"),
            ("DummyJSON", "https://dummyjson.com/carts/user/1"),
        ]

        for api_name, url in protected_endpoints:
            self.log("TEST", f"Testing token validation: {url}")

            for token_name, token_value in test_tokens:
                try:
                    response = self.session.get(
                        url, headers={"Authorization": token_value}, timeout=10
                    )
                    status = response.status_code

                    if status == 200:
                        self.log("CRIT", f"  ⚠ {token_name}: Accepted! (HTTP {status})")
                        self.add_finding(
                            "HIGH",
                            f"[{api_name}] Weak Token Validation — {token_name}",
                            f"The endpoint {url} accepted an invalid token ({token_name}: "
                            f"'{token_value}'). This means the authentication check is either "
                            f"missing or improperly implemented, allowing unauthorized access.",
                            "Implement strict token validation: verify signature, check expiration, "
                            "validate issuer/audience claims. Use established JWT libraries."
                        )
                    elif status in [401, 403]:
                        self.log("PASS", f"  ✓ {token_name}: Properly rejected (HTTP {status})")
                    else:
                        self.log("INFO", f"  ? {token_name}: HTTP {status}")

                except Exception as e:
                    self.log("WARN", f"  Error with {token_name}: {e}")

    # ========================================================================
    # Test 3: IDOR (Insecure Direct Object Reference)
    # ========================================================================
    def test_idor(self):
        """Test for IDOR vulnerabilities by accessing other users' resources."""
        print(f"\n{Fore.MAGENTA}{'─' * 60}")
        print(f"  TEST 3: IDOR (Insecure Direct Object Reference)")
        print(f"{'─' * 60}\n")

        idor_endpoints = [
            ("JSONPlaceholder", "https://jsonplaceholder.typicode.com/users/{id}", range(1, 11)),
            ("DummyJSON", "https://dummyjson.com/users/{id}", range(1, 11)),
            ("DummyJSON", "https://dummyjson.com/carts/{id}", range(1, 6)),
            ("ReqRes", "https://reqres.in/api/users/{id}", range(1, 13)),
        ]

        for api_name, url_template, id_range in idor_endpoints:
            self.log("TEST", f"Testing IDOR: {url_template}")
            accessible = []

            for test_id in id_range:
                url = url_template.replace("{id}", str(test_id))
                try:
                    response = self.session.get(url, timeout=10)
                    if response.status_code == 200:
                        accessible.append(test_id)
                except Exception:
                    pass
                time.sleep(0.1)

            if len(accessible) > 1:
                self.log("CRIT", f"  ⚠ Enumerated {len(accessible)} records: IDs {accessible}")
                self.add_finding(
                    "MEDIUM",
                    f"[{api_name}] IDOR — Sequential ID Enumeration",
                    f"The endpoint {url_template} uses sequential numeric IDs that can be "
                    f"enumerated. Successfully accessed {len(accessible)} records (IDs: "
                    f"{accessible[:5]}...). Without proper authorization checks, any user "
                    f"can access any other user's data by guessing/incrementing the ID.",
                    "Use UUIDs instead of sequential IDs. Implement authorization checks to "
                    "verify the requesting user has permission to access the requested resource."
                )
            else:
                self.log("PASS", f"  ✓ Only {len(accessible)} record(s) accessible")

    # ========================================================================
    # Test 4: Registration & Login Security
    # ========================================================================
    def test_registration_security(self):
        """Test registration and login endpoint security."""
        print(f"\n{Fore.MAGENTA}{'─' * 60}")
        print(f"  TEST 4: Registration & Login Security")
        print(f"{'─' * 60}\n")

        # Test ReqRes registration
        self.log("TEST", "Testing ReqRes registration endpoint")

        # Test with weak password
        weak_creds = [
            {"email": "test@test.com", "password": "123"},
            {"email": "test@test.com", "password": "a"},
            {"email": "not-an-email", "password": "password123"},
        ]

        for creds in weak_creds:
            try:
                response = self.session.post(
                    "https://reqres.in/api/register",
                    json=creds, timeout=10
                )
                if response.status_code in [200, 201]:
                    self.log("WARN", f"  ⚠ Weak credentials accepted: {creds}")
                elif response.status_code == 400:
                    error = response.json().get("error", "")
                    self.log("INFO", f"  Rejected ({error}): {creds}")
            except Exception as e:
                self.log("WARN", f"  Error: {e}")

        # Test DummyJSON login
        self.log("TEST", "Testing DummyJSON login endpoint")
        login_tests = [
            {"username": "emilys", "password": "emilyspass"},  # Valid credentials (from docs)
            {"username": "admin", "password": "admin"},
            {"username": "' OR 1=1 --", "password": "anything"},
        ]

        for creds in login_tests:
            try:
                response = self.session.post(
                    "https://dummyjson.com/auth/login",
                    json=creds, timeout=10
                )
                data = response.json()
                if response.status_code == 200 and "token" in str(data).lower():
                    if creds["username"] in ["admin", "' OR 1=1 --"]:
                        self.log("CRIT", f"  ⚠ Suspicious login succeeded: {creds['username']}")
                    else:
                        self.log("INFO", f"  Valid login successful: {creds['username']}")
                        # Check what's returned in login response
                        sensitive_in_response = [k for k in data.keys() if k not in
                                                 ["token", "refreshToken", "id", "username", "message"]]
                        if sensitive_in_response:
                            self.log("WARN", f"  ⚠ Extra data in login response: {sensitive_in_response}")
                            self.add_finding(
                                "MEDIUM",
                                "[DummyJSON] Excessive Data in Login Response",
                                f"The login endpoint returns unnecessary data beyond the auth token: "
                                f"{', '.join(sensitive_in_response)}. Login responses should contain "
                                f"minimal data (token + basic user identifier).",
                                "Return only the authentication token and minimal user info (user ID) "
                                "in login responses. Additional user data should be fetched via "
                                "separate authenticated API calls."
                            )
                else:
                    self.log("PASS", f"  ✓ Invalid login rejected: {creds['username']}")
            except Exception as e:
                self.log("WARN", f"  Error: {e}")

    # ========================================================================
    # Run All Tests
    # ========================================================================
    def run_all(self):
        """Execute all authentication and authorization tests."""
        print(f"""
{Fore.CYAN}
    ╔══════════════════════════════════════════════════════════╗
    ║       🔑 AUTHENTICATION & AUTHORIZATION TESTER          ║
    ║                                                          ║
    ║  Tests: Unauth Access, Token Validation, IDOR, Login    ║
    ║  Author: Shashank K                                      ║
    ╚══════════════════════════════════════════════════════════╝
{Style.RESET_ALL}""")

        start = datetime.now()

        self.test_unauthenticated_access()
        self.test_token_validation()
        self.test_idor()
        self.test_registration_security()

        elapsed = (datetime.now() - start).total_seconds()

        print(f"\n{'=' * 60}")
        print(f"{Fore.CYAN}  📊 AUTH TEST SUMMARY")
        print(f"{'=' * 60}")
        print(f"  Duration: {elapsed:.1f}s")
        print(f"  Total Findings: {len(self.findings)}")

        severity_counts = {}
        for f in self.findings:
            severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1
        for sev in ["HIGH", "MEDIUM", "LOW"]:
            print(f"    {sev}: {severity_counts.get(sev, 0)}")

        # Save results
        results = {"test": "Authentication & Authorization", "findings": self.findings}
        with open("evidence/auth_test_results.json", "w") as f:
            json.dump(results, f, indent=2)
        self.log("PASS", "Results saved to evidence/auth_test_results.json")


if __name__ == "__main__":
    tester = AuthTester()
    tester.run_all()

