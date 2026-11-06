import urllib.parse
from scanner.modules.base_module import BaseModule
from scanner.http_client import SafeHTTPClient

class XSSCheckModule(BaseModule):
    @property
    def name(self) -> str:
        return "Passive Reflected XSS Probing"

    def run(self, target_url: str) -> list[dict]:
        findings = []
        parsed = urllib.parse.urlparse(target_url)
        params = urllib.parse.parse_qs(parsed.query)

        if not params:
            return findings

        canary_payload = "SecScanXSSProbeTest"

        for param in params:
            test_params = params.copy()
            test_params[param] = [f"<{canary_payload}>"]
            new_query = urllib.parse.urlencode(test_params, doseq=True)
            test_url = urllib.parse.urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))

            try:
                _, _, body = SafeHTTPClient.request(test_url, method="GET")
                if f"<{canary_payload}>" in body:
                    findings.append({
                        'name': f"Reflected XSS in parameter '{param}'",
                        'severity': 'HIGH',
                        'description': "Unencoded HTML characters injected in parameter were reflected back in the response body.",
                        'evidence': f"Unescaped tag <{canary_payload}> reflected in page output.",
                        'remediation': "Contextually encode all user-controllable input rendered in web pages."
                    })
            except Exception:
                continue

        return findings
