#!/usr/bin/env python3
"""
Rate Limiting Tester
=====================
Tests API endpoints for rate limiting enforcement:
- Burst request testing
- Rate limit header analysis
- Gradual ramp-up testing
- Per-endpoint rate comparison

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


class RateLimitTester:
    """Tests API rate limiting implementation."""

    def __init__(self):
        self.findings = []
        self.results = {}

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

    def test_burst(self, api_name, url, burst_size=30):
        """Send a burst of requests and check for rate limiting."""
        self.log("TEST", f"Burst test ({burst_size} requests): {url}")

        statuses = []
        response_times = []
        rate_limit_headers = {}

        for i in range(burst_size):
            start = time.time()
            try:
                response = requests.get(url, timeout=10, headers={
                    "User-Agent": "RateLimitTester/1.0"
                })
                elapsed = time.time() - start
                statuses.append(response.status_code)
                response_times.append(elapsed)

                # Capture rate limit headers from last response
                for h in ["X-RateLimit-Limit", "X-RateLimit-Remaining",
                           "X-RateLimit-Reset", "Retry-After",
                           "RateLimit-Limit", "RateLimit-Remaining",
                           "RateLimit-Reset"]:
                    val = response.headers.get(h)
                    if val:
                        rate_limit_headers[h] = val

                if response.status_code == 429:
                    self.log("PASS", f"  ✓ Rate limited at request #{i + 1} (HTTP 429)")
                    break

            except requests.exceptions.Timeout:
                self.log("WARN", f"  Timeout at request #{i + 1}")
            except Exception as e:
                self.log("WARN", f"  Error at request #{i + 1}: {e}")

            time.sleep(0.05)  # Minimal delay between requests

        # Analyze results
        success_count = statuses.count(200)
        rate_limited_count = statuses.count(429)
        avg_time = sum(response_times) / len(response_times) if response_times else 0

        result = {
            "api": api_name,
            "url": url,
            "burst_size": burst_size,
            "success_count": success_count,
            "rate_limited_count": rate_limited_count,
            "avg_response_ms": round(avg_time * 1000, 1),
            "rate_limit_headers": rate_limit_headers,
            "is_rate_limited": rate_limited_count > 0 or bool(rate_limit_headers),
        }

        self.results[f"{api_name}:{url}"] = result

        if not result["is_rate_limited"]:
            self.log("CRIT", f"  ⚠ NO rate limiting: {success_count}/{burst_size} requests succeeded")
            self.add_finding(
                "MEDIUM",
                f"[{api_name}] No Rate Limiting on {url}",
                f"Sent {burst_size} rapid requests — all {success_count} returned HTTP 200 "
                f"with no rate limiting headers. Average response time: {result['avg_response_ms']}ms. "
                f"This makes the API vulnerable to:\n"
                f"• Brute-force attacks\n"
                f"• Denial of Service (DoS)\n"
                f"• Data scraping\n"
                f"• Resource exhaustion",
                "Implement rate limiting:\n"
                "- 429 Too Many Requests after threshold\n"
                "- X-RateLimit-Limit, X-RateLimit-Remaining headers\n"
                "- Different limits per endpoint (login stricter than read)\n"
                "- Consider IP-based + token-based limits"
            )
        else:
            self.log("PASS", f"  ✓ Rate limiting detected")
            if rate_limit_headers:
                self.log("INFO", f"    Headers: {json.dumps(rate_limit_headers)}")

        return result

    def test_login_rate_limit(self):
        """Test rate limiting on login/auth endpoints specifically."""
        self.log("TEST", "Testing login endpoint rate limiting")

        login_endpoints = [
            ("ReqRes", "https://reqres.in/api/login",
             {"email": "peter@klaven", "password": "wrong"}),
            ("DummyJSON", "https://dummyjson.com/auth/login",
             {"username": "invalid_user", "password": "wrongpass"}),
        ]

        for api_name, url, payload in login_endpoints:
            self.log("TEST", f"Brute-force simulation: {url}")
            failed_attempts = 0
            locked = False

            for i in range(15):
                try:
                    response = requests.post(url, json=payload, timeout=10)
                    if response.status_code == 429:
                        self.log("PASS", f"  ✓ Account protection kicked in at attempt #{i + 1}")
                        locked = True
                        break
                    elif response.status_code in [400, 401]:
                        failed_attempts += 1
                except Exception:
                    pass
                time.sleep(0.1)

            if not locked and failed_attempts > 10:
                self.log("CRIT", f"  ⚠ {failed_attempts} failed logins — no lockout/rate limit")
                self.add_finding(
                    "HIGH",
                    f"[{api_name}] No Brute-Force Protection on Login",
                    f"Submitted {failed_attempts} failed login attempts with no account lockout "
                    f"or rate limiting. Attackers can perform unlimited credential stuffing or "
                    f"brute-force attacks against user accounts.",
                    "Implement progressive delays or account lockout after failed attempts:\n"
                    "- Lock account after 5-10 failed attempts\n"
                    "- Implement exponential backoff (1s, 2s, 4s, 8s...)\n"
                    "- Use CAPTCHA after 3 failed attempts\n"
                    "- Send security alerts to account owner"
                )

    def run_all(self):
        """Execute all rate limiting tests."""
        print(f"""
{Fore.CYAN}
    ╔══════════════════════════════════════════════════════════╗
    ║           ⏱  RATE LIMITING TESTER                       ║
    ║                                                          ║
    ║  Tests: Burst Requests, Login Brute-Force, Headers      ║
    ║  Author: Shashank K                                      ║
    ╚══════════════════════════════════════════════════════════╝
{Style.RESET_ALL}""")

        start = datetime.now()

        # Test general endpoints
        endpoints = [
            ("JSONPlaceholder", "https://jsonplaceholder.typicode.com/posts"),
            ("ReqRes", "https://reqres.in/api/users"),
            ("DummyJSON", "https://dummyjson.com/products"),
            ("HTTPBin", "https://httpbin.org/get"),
            ("REST Countries", "https://restcountries.com/v3.1/alpha/US"),
        ]

        for api_name, url in endpoints:
            self.test_burst(api_name, url)
            time.sleep(1)  # Pause between APIs

        # Test login endpoints specifically
        self.test_login_rate_limit()

        elapsed = (datetime.now() - start).total_seconds()

        # Print summary table
        print(f"\n{'=' * 60}")
        print(f"{Fore.CYAN}  ⏱  RATE LIMITING TEST SUMMARY")
        print(f"{'=' * 60}")

        table_data = []
        for key, result in self.results.items():
            status = "✓ Protected" if result["is_rate_limited"] else "⚠ Not Protected"
            table_data.append([
                result["api"],
                f"{result['success_count']}/{result['burst_size']}",
                f"{result['avg_response_ms']}ms",
                "Yes" if result["rate_limit_headers"] else "No",
                status,
            ])

        print(tabulate(table_data,
                        headers=["API", "Success/Total", "Avg Time", "Rate Headers", "Status"],
                        tablefmt="grid"))

        print(f"\n  Duration: {elapsed:.1f}s | Findings: {len(self.findings)}")

        # Save results
        with open("evidence/rate_limit_results.json", "w") as f:
            json.dump({"findings": self.findings, "results": self.results}, f, indent=2)
        self.log("PASS", "Results saved to evidence/rate_limit_results.json")


if __name__ == "__main__":
    tester = RateLimitTester()
    tester.run_all()

