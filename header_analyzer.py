#!/usr/bin/env python3
"""
HTTP Security Headers Analyzer
================================
Analyzes API responses for security-related HTTP headers,
compares against best practices, and generates a security score.

Author: Shashank K
Date: November 2026
"""

import requests
import json
from datetime import datetime
from colorama import init, Fore, Style
from tabulate import tabulate

init(autoreset=True)


# Security headers with their recommended values and risk descriptions
HEADER_CHECKS = {
    "Strict-Transport-Security": {
        "recommended": "max-age=31536000; includeSubDomains; preload",
        "risk": "Without HSTS, browsers may connect over HTTP, enabling man-in-the-middle attacks.",
        "severity": "HIGH",
        "category": "Transport Security",
    },
    "Content-Security-Policy": {
        "recommended": "default-src 'self'; script-src 'self'",
        "risk": "Without CSP, the application is more vulnerable to XSS and data injection attacks.",
        "severity": "MEDIUM",
        "category": "Content Security",
    },
    "X-Content-Type-Options": {
        "recommended": "nosniff",
        "risk": "Without this header, browsers may MIME-sniff responses, leading to XSS via content type confusion.",
        "severity": "MEDIUM",
        "category": "Content Security",
    },
    "X-Frame-Options": {
        "recommended": "DENY",
        "risk": "Without this header, the page can be embedded in iframes, enabling clickjacking attacks.",
        "severity": "MEDIUM",
        "category": "UI Security",
    },
    "X-XSS-Protection": {
        "recommended": "0 (or rely on CSP)",
        "risk": "Legacy header. Modern browsers use CSP instead. Setting to '1; mode=block' can introduce vulnerabilities.",
        "severity": "LOW",
        "category": "Legacy Protection",
    },
    "Referrer-Policy": {
        "recommended": "strict-origin-when-cross-origin",
        "risk": "Without a referrer policy, the full URL (including query parameters with tokens) may leak to third parties.",
        "severity": "MEDIUM",
        "category": "Privacy",
    },
    "Permissions-Policy": {
        "recommended": "geolocation=(), camera=(), microphone=()",
        "risk": "Without this header, embedded content may access device features like camera and microphone.",
        "severity": "LOW",
        "category": "Privacy",
    },
    "Cache-Control": {
        "recommended": "no-store, no-cache, must-revalidate",
        "risk": "Without proper cache control, sensitive API responses may be cached by proxies or browsers.",
        "severity": "MEDIUM",
        "category": "Data Protection",
    },
    "Access-Control-Allow-Origin": {
        "recommended": "Specific origin (not *)",
        "risk": "Wildcard (*) CORS allows any website to read API responses, risking data exposure.",
        "severity": "HIGH",
        "category": "CORS",
    },
}

# Headers that should NOT be present (information disclosure)
UNWANTED_HEADERS = {
    "Server": "Reveals web server technology and version, helping attackers find specific exploits.",
    "X-Powered-By": "Reveals backend framework/language, aiding targeted attacks.",
    "X-AspNet-Version": "Reveals ASP.NET version, enabling version-specific attacks.",
    "X-AspNetMvc-Version": "Reveals ASP.NET MVC version.",
}


class HeaderAnalyzer:
    """Analyzes HTTP security headers for API endpoints."""

    def __init__(self):
        self.findings = []
        self.api_scores = {}

    def log(self, level, msg):
        colors = {"INFO": Fore.CYAN, "WARN": Fore.YELLOW, "CRIT": Fore.RED,
                  "PASS": Fore.GREEN, "TEST": Fore.MAGENTA}
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] {colors.get(level, Fore.WHITE)}[{level}]{Style.RESET_ALL} {msg}")

    def analyze_endpoint(self, api_name, url):
        """Analyze security headers for a single endpoint."""
        print(f"\n{Fore.MAGENTA}{'─' * 60}")
        print(f"  Analyzing: {api_name}")
        print(f"  URL: {url}")
        print(f"{'─' * 60}\n")

        try:
            response = requests.get(url, timeout=10, headers={
                "User-Agent": "HeaderAnalyzer/1.0 (Educational)"
            })
        except Exception as e:
            self.log("WARN", f"Failed to connect: {e}")
            return

        headers = dict(response.headers)
        score = 0
        max_score = len(HEADER_CHECKS)
        present = []
        missing = []
        misconfigured = []

        # Check required security headers
        for header_name, check in HEADER_CHECKS.items():
            value = headers.get(header_name)

            if value:
                present.append((header_name, value))
                # Specific checks
                if header_name == "Access-Control-Allow-Origin" and value == "*":
                    misconfigured.append((header_name, value, check["recommended"]))
                    self.log("WARN", f"  ⚠ {header_name}: {value} (should be specific origin)")
                    score += 0.5
                elif header_name == "Strict-Transport-Security":
                    if "max-age=" in value:
                        max_age = int(value.split("max-age=")[1].split(";")[0].strip())
                        if max_age < 31536000:
                            misconfigured.append((header_name, value, check["recommended"]))
                            self.log("WARN", f"  ⚠ {header_name}: max-age too short ({max_age})")
                            score += 0.5
                        else:
                            self.log("PASS", f"  ✓ {header_name}: {value}")
                            score += 1
                    else:
                        score += 1
                else:
                    self.log("PASS", f"  ✓ {header_name}: {value}")
                    score += 1
            else:
                missing.append((header_name, check))
                self.log("WARN", f"  ✗ {header_name}: MISSING (Risk: {check['severity']})")

        # Check for unwanted headers
        print()
        disclosed = []
        for header_name, risk in UNWANTED_HEADERS.items():
            value = headers.get(header_name)
            if value:
                disclosed.append((header_name, value))
                self.log("WARN", f"  ⚠ {header_name}: {value} (should be removed)")
                score -= 0.5

        # Calculate score
        percentage = max(0, (score / max_score) * 100)
        grade = "A" if percentage >= 90 else "B" if percentage >= 75 else "C" if percentage >= 60 else "D" if percentage >= 40 else "F"

        self.api_scores[api_name] = {
            "url": url,
            "score": round(percentage, 1),
            "grade": grade,
            "present": len(present),
            "missing": len(missing),
            "misconfigured": len(misconfigured),
            "disclosed": len(disclosed),
        }

        # Generate findings for missing critical headers
        critical_missing = [(h, c) for h, c in missing if c["severity"] in ["HIGH", "MEDIUM"]]
        if critical_missing:
            header_list = "\n".join([f"- **{h}**: {c['risk']}" for h, c in critical_missing])
            self.findings.append({
                "severity": "MEDIUM",
                "title": f"[{api_name}] {len(critical_missing)} Critical Security Headers Missing",
                "description": f"The following security headers are missing:\n{header_list}\n\n"
                               f"Security Header Score: {percentage:.0f}% (Grade: {grade})",
                "recommendation": "Add the missing security headers to all API responses. "
                                  "Use a middleware or reverse proxy to set these headers globally.",
            })

        if disclosed:
            disc_list = "\n".join([f"- {h}: {v}" for h, v in disclosed])
            self.findings.append({
                "severity": "LOW",
                "title": f"[{api_name}] Server Technology Disclosed via Headers",
                "description": f"The following headers reveal server technology:\n{disc_list}",
                "recommendation": "Remove or suppress these headers in production. "
                                  "Use reverse proxy configuration to strip them.",
            })

        # Print header score
        grade_colors = {"A": Fore.GREEN, "B": Fore.GREEN, "C": Fore.YELLOW, "D": Fore.YELLOW, "F": Fore.RED}
        color = grade_colors.get(grade, Fore.WHITE)
        print(f"\n  {color}Security Header Score: {percentage:.0f}% (Grade: {grade}){Style.RESET_ALL}")
        print(f"  Present: {len(present)} | Missing: {len(missing)} | "
              f"Misconfigured: {len(misconfigured)} | Disclosed: {len(disclosed)}")

    def run_all(self):
        """Analyze all target APIs."""
        print(f"""
{Fore.CYAN}
    ╔══════════════════════════════════════════════════════════╗
    ║         🛡  HTTP SECURITY HEADERS ANALYZER              ║
    ║                                                          ║
    ║  Checks: HSTS, CSP, CORS, Cache, Info Disclosure        ║
    ║  Author: Shashank K                                      ║
    ╚══════════════════════════════════════════════════════════╝
{Style.RESET_ALL}""")

        apis = [
            ("JSONPlaceholder", "https://jsonplaceholder.typicode.com/users"),
            ("ReqRes", "https://reqres.in/api/users"),
            ("HTTPBin", "https://httpbin.org/get"),
            ("DummyJSON", "https://dummyjson.com/products"),
            ("REST Countries", "https://restcountries.com/v3.1/alpha/US"),
        ]

        for api_name, url in apis:
            self.analyze_endpoint(api_name, url)

        # Print summary scorecard
        print(f"\n\n{'=' * 60}")
        print(f"{Fore.CYAN}  🛡  SECURITY HEADERS SCORECARD")
        print(f"{'=' * 60}\n")

        table_data = []
        for api_name, data in self.api_scores.items():
            grade_icon = {"A": "🟢", "B": "🟢", "C": "🟡", "D": "🟠", "F": "🔴"}.get(data["grade"], "⚪")
            table_data.append([
                api_name,
                f"{grade_icon} {data['grade']}",
                f"{data['score']}%",
                data["present"],
                data["missing"],
                data["misconfigured"],
            ])

        print(tabulate(table_data,
                        headers=["API", "Grade", "Score", "Present", "Missing", "Misconfig"],
                        tablefmt="grid"))

        print(f"\n  Total Findings: {len(self.findings)}")

        # Save results
        results = {
            "scores": self.api_scores,
            "findings": self.findings,
            "header_checks": {k: {"recommended": v["recommended"], "severity": v["severity"]}
                              for k, v in HEADER_CHECKS.items()},
        }
        with open("evidence/header_analysis_results.json", "w") as f:
            json.dump(results, f, indent=2)
        self.log("PASS", "Results saved to evidence/header_analysis_results.json")


if __name__ == "__main__":
    analyzer = HeaderAnalyzer()
    analyzer.run_all()

