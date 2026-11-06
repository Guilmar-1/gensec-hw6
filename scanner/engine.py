from models.scan_model import ScanModel
from models.vulnerability_model import VulnerabilityModel
from scanner.validator import URLValidator
from scanner.modules.headers_check import HeadersCheckModule
from scanner.modules.sensitive_files import SensitiveFilesModule
from scanner.modules.sqli_check import SQLiCheckModule
from scanner.modules.xss_check import XSSCheckModule

class ScannerEngine:
    def __init__(self):
        self.modules = [
            HeadersCheckModule(),
            SensitiveFilesModule(),
            SQLiCheckModule(),
            XSSCheckModule()
        ]

    def run_scan(self, scan_id: int, target_url: str):
        is_valid, msg = URLValidator.validate_url(target_url)
        if not is_valid:
            ScanModel.update_scan_status(scan_id, 'failed', 0)
            VulnerabilityModel.create_vulnerability(
                scan_id=scan_id,
                name="Validation Error",
                severity="CRITICAL",
                description="Scan target failed security validation.",
                evidence=msg,
                remediation="Ensure target URL points to allowed loopback/private subnets."
            )
            return

        ScanModel.update_scan_status(scan_id, 'running')
        all_findings = []

        for module in self.modules:
            try:
                module_findings = module.run(target_url)
                all_findings.extend(module_findings)
            except Exception as e:
                all_findings.append({
                    'name': f"Module Execution Error: {module.name}",
                    'severity': 'LOW',
                    'description': "Module encountered an error during execution.",
                    'evidence': str(e),
                    'remediation': "Review target status and scanner logs."
                })

        for finding in all_findings:
            VulnerabilityModel.create_vulnerability(
                scan_id=scan_id,
                name=finding['name'],
                severity=finding['severity'],
                description=finding['description'],
                evidence=finding.get('evidence', ''),
                remediation=finding.get('remediation', '')
            )

        ScanModel.update_scan_status(scan_id, 'completed', len(all_findings))
