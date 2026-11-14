# 🔐 API Security Risk Analysis Project

![Security](https://img.shields.io/badge/Security-API%20Analysis-red)
![Status](https://img.shields.io/badge/Status-Completed-brightgreen)
![Tools](https://img.shields.io/badge/Tools-Postman%20%7C%20DevTools%20%7C%20Python-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)

## 📋 Project Overview

A comprehensive **API Security Risk Analysis** project that identifies, analyzes, and documents security vulnerabilities in public APIs. This project demonstrates practical cybersecurity assessment skills including authentication analysis, authorization testing, rate-limiting evaluation, and input validation testing.

> ⚠️ **Disclaimer**: This project is for **educational and authorized testing purposes only**. All APIs tested are publicly available demo/test APIs. Never test APIs without proper authorization.

---

## 🎯 Objectives

- ✅ Identify insecure API endpoints and data exposure risks
- ✅ Analyze authentication & authorization issues (tokens, keys, access control)
- ✅ Detect missing rate-limiting or input validation gaps
- ✅ Explain API risks in simple, business-friendly language
- ✅ Deliver a professional API Security Risk Analysis Report

---

## 🛠️ Tools Used

| Tool | Purpose |
|------|---------|
| **Postman / Insomnia** | API endpoint testing & request crafting |
| **Browser DevTools** | Network traffic analysis & header inspection |
| **Python Scripts** | Automated security testing & vulnerability scanning |
| **Public Test APIs** | Safe targets for security analysis |
| **Markdown / PDF** | Professional report documentation |

---

## 📂 Project Structure

```
API-Security-Risk-Analysis/
│
├── README.md                          # Project overview (this file)
├── LICENSE                            # MIT License
│
├── scripts/                           # Automated testing scripts
│   ├── api_security_scanner.py        # Main API security scanner
│   ├── auth_tester.py                 # Authentication & authorization tester
│   ├── rate_limit_tester.py           # Rate-limiting analysis tool
│   ├── input_validation_tester.py     # Input validation & injection tester
│   ├── header_analyzer.py             # HTTP security headers analyzer
│   └── requirements.txt               # Python dependencies
│
├── postman-collections/               # Postman/Insomnia collections
│   └── api_security_tests.json        # Importable test collection
│
├── evidence/                          # Screenshots & evidence artifacts
│   └── README.md                      # Evidence documentation guide
│
├── reports/                           # Final deliverable reports
│   └── API_Security_Risk_Analysis_Report.md  # Full professional report
│
└── docs/                              # Supporting documentation
    ├── METHODOLOGY.md                 # Testing methodology & framework
    ├── API_ENDPOINTS_TESTED.md        # List of all tested endpoints
    └── OWASP_API_TOP10_REFERENCE.md   # OWASP API Security Top 10 mapping
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- pip (Python package manager)
- Postman or Insomnia (optional, for manual testing)

### Setup
```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/API-Security-Risk-Analysis.git
cd API-Security-Risk-Analysis

# Install dependencies
pip install -r scripts/requirements.txt

# Run the full security scan
python scripts/api_security_scanner.py

# Run individual tests
python scripts/auth_tester.py
python scripts/rate_limit_tester.py
python scripts/input_validation_tester.py
python scripts/header_analyzer.py
```

---

## 🔍 APIs Tested

| API | URL | Purpose |
|-----|-----|---------|
| JSONPlaceholder | https://jsonplaceholder.typicode.com | REST API simulation (no auth) |
| ReqRes | https://reqres.in | Auth token testing |
| HTTPBin | https://httpbin.org | Request/response inspection |
| DummyJSON | https://dummyjson.com | Authentication & product API |
| REST Countries | https://restcountries.com | Public data API |

---

## 📊 Key Findings Summary

| Risk Category | Severity | Count |
|--------------|----------|-------|
| 🔴 Critical | High | 3 |
| 🟠 High | Medium-High | 4 |
| 🟡 Medium | Medium | 5 |
| 🟢 Low | Low | 3 |

> 📄 See the [Full Report](reports/API_Security_Risk_Analysis_Report.md) for detailed findings and remediation recommendations.

---

## 🧠 Skills Demonstrated

- **API Security Analysis** — Systematic vulnerability identification
- **Authentication & Authorization Assessment** — Token handling, key management, access control
- **Risk Identification** — OWASP API Top 10 mapping
- **Security Documentation** — Business-friendly risk communication
- **SaaS Security Fundamentals** — Cloud API security principles

---

## 📄 Deliverable

The main deliverable is the **[API Security Risk Analysis Report](reports/API_Security_Risk_Analysis_Report.md)** which includes:
- Executive Summary
- Methodology & Scope
- Detailed Vulnerability Findings
- Risk Impact Assessment (Business Language)
- Remediation Recommendations
- OWASP API Top 10 Mapping
- Evidence & Screenshots Guide

---

## 📜 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Shashank K**  
Cybersecurity Enthusiast | API Security Analyst

---

## 🙏 Acknowledgments

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- Public test API providers (JSONPlaceholder, ReqRes, HTTPBin, DummyJSON)
- Cybersecurity community resources

