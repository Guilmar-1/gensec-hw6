import urllib.parse
from scanner.modules.base_module import BaseModule
from scanner.http_client import SafeHTTPClient

class SQLiCheckModule(BaseModule):
    @property
    def name(self) -> str:
        return "Passive SQL Injection Probing"

    def run(self, target_url: str) -> list[dict]:
        findings = []
        parsed = urllib.parse.urlparse(target_url)
        params = urllib.parse.parse_qs(parsed.query)

        if not params:
            return findings

        sqli_error_signatures = [
            "SQL syntax",
            "sqlite3.OperationalError",
            "MySQLQueryResult",
            "PostgreSQL query failed",
            "unclosed quotation mark"
        ]

        for param in params:
            test_params = params.copy()
            test_params[param] = ["'"]
            new_query = urllib.parse.urlencode(test_params, doseq=True)
            test_url = urllib.parse.urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))

            try:
                status, _, body = SafeHTTPClient.request(test_url, method="GET")
                for sig in sqli_error_signatures:
                    if sig.lower() in body.lower():
                        findings.append({
                            'name': f"Potential SQL Injection in parameter '{param}'",
                            'severity': 'HIGH',
                            'description': "Non-destructive single-quote payload triggered a SQL error response.",
                            'evidence': f"Found database error string '{sig}' in response for payload on parameter '{param}'.",
                            'remediation': "Use parameterized queries or prepared statements."
                        })
                        break
            except Exception:
                continue

        return findings
