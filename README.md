# Web Security Scanner

A lightweight, modular, and non-destructive web security scanner built with Flask, Jinja2, and SQLite. Designed for local vulnerability assessments of applications such as OWASP Juice Shop running on local/private networks.

---

## Features

- **Dashboard UI**: Modern cybersecurity-styled interface for triggering scans and inspecting findings.
- **Vulnerability Checks**:
  - Security Headers Audit (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Server disclosure).
  - Sensitive File Exposure (`.env`, `.git/HEAD`, `robots.txt`, `package.json`).
  - Safe Reflected XSS Probing.
  - Safe SQL Injection Probing.
- **Security Protections**:
  - **SSRF Protection**: Resolves domain hostnames and restricts scans exclusively to loopback (`127.0.0.0/8`, `::1/128`) and private IP ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
  - **Request Limits**: Enforces HTTP timeouts (5s) and response size limits (2MB).
  - **Safe Redirects**: Limits redirect loops and validates redirect destination IPs against SSRF filters.
- **Reporting**: Export findings in JSON, CSV, or formatted HTML summary reports.

---

## Installation & Setup

1. **Clone & Environment Setup**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install flask pytest requests
   ```

2. **Run the Application**:
   ```bash
   python app.py
   ```
   The web dashboard will be available at `http://127.0.0.1:5000`.

---

## Scanning a Target (e.g., OWASP Juice Shop)

1. Start OWASP Juice Shop locally (e.g., on `http://127.0.0.1:3000`).
2. Open `http://127.0.0.1:5000` in your browser.
3. Enter `http://127.0.0.1:3000` in the target URL field.
4. Click **Start Security Scan**.
5. View vulnerability metrics, detailed findings, evidence excerpts, and remediation instructions.
6. Export the report in JSON or CSV format.

---

## Running Automated Tests

To execute all unit and integration tests:

