from scanner.modules.base_module import BaseModule
from scanner.http_client import SafeHTTPClient

class HeadersCheckModule(BaseModule):
    @property
    def name(self) -> str:
        return "Security Headers Audit"

    def run(self, target_url: str) -> list[dict]:
        findings = []
        try:
            status, headers, _ = SafeHTTPClient.request(target_url, method="GET")
            headers_lower = {k.lower(): v for k, v in headers.items()}

            security_headers = {
                'x-frame-options': ('MEDIUM', 'Missing X-Frame-Options header makes site vulnerable to Clickjacking.', 'Add X-Frame-Options: DENY or SAMEORIGIN.'),
                'x-content-type-options': ('LOW', 'Missing X-Content-Type-Options header allows MIME-sniffing.', 'Add X-Content-Type-Options: nosniff.'),
                'content-security-policy': ('MEDIUM', 'Missing Content-Security-Policy (CSP) header.', 'Define a robust Content-Security-Policy header.'),
                'strict-transport-security': ('LOW', 'Missing HTTP Strict Transport Security (HSTS) header.', 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains.')
            }

            for header_name, (severity, desc, remediation) in security_headers.items():
                if header_name not in headers_lower:
                    findings.append({
                        'name': f"Missing Security Header: {header_name}",
                        'severity': severity,
                        'description': desc,
                        'evidence': f"Target returned status {status} without standard header '{header_name}'",
                        'remediation': remediation
                    })

            if 'x-powered-by' in headers_lower or 'server' in headers_lower:
                server_info = headers_lower.get('x-powered-by', headers_lower.get('server', ''))
                findings.append({
                    'name': "Information Disclosure: Server Version Header",
                    'severity': 'LOW',
                    'description': "Server exposes detailed component or technology stack information.",
                    'evidence': f"Server header value: '{server_info}'",
                    'remediation': "Configure HTTP server to suppress version headers (Server, X-Powered-By)."
                })
        except Exception as e:
            findings.append({
                'name': "Security Headers Audit Failed",
                'severity': 'LOW',
                'description': "Could not complete headers inspection.",
                'evidence': str(e),
                'remediation': "Verify connectivity to target application."
            })
        return findings
