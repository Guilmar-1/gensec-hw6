import urllib.parse
from scanner.modules.base_module import BaseModule
from scanner.http_client import SafeHTTPClient

class SensitiveFilesModule(BaseModule):
    @property
    def name(self) -> str:
        return "Sensitive Files Discovery"

    def run(self, target_url: str) -> list[dict]:
        findings = []
        paths_to_check = [
            ('/.env', 'HIGH', 'Environment file exposing database or API secrets.'),
            ('/.git/HEAD', 'HIGH', 'Exposed Git repository directory structure.'),
            ('/robots.txt', 'LOW', 'Exposed robots.txt file detailing site paths.'),
            ('/package.json', 'LOW', 'Exposed Node.js dependencies manifest.')
        ]

        base_parsed = urllib.parse.urlparse(target_url)

        for path, severity, desc in paths_to_check:
            test_url = urllib.parse.urljoin(f"{base_parsed.scheme}://{base_parsed.netloc}", path)
            try:
                status, _, body = SafeHTTPClient.request(test_url, method="GET")
                if status == 200 and len(body.strip()) > 0:
                    findings.append({
                        'name': f"Exposed Sensitive Path: {path}",
                        'severity': severity,
                        'description': desc,
                        'evidence': f"HTTP {status} returned for endpoint '{path}'. Excerpt: {body[:100]}...",
                        'remediation': f"Restrict public web access to path '{path}'."
                    })
            except Exception:
                continue

        return findings
