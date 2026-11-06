import unittest
import os
import tempfile
from app import create_app
from config import Config
from models.scan_model import ScanModel
from models.vulnerability_model import VulnerabilityModel

class TestModels(unittest.TestCase):
    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp()
        Config.DATABASE = self.db_path
        self.app = create_app()
        self.app_context = self.app.app_context()
        self.app_context.push()

    def tearDown(self):
        self.app_context.pop()
        os.close(self.db_fd)
        os.remove(self.db_path)

    def test_scan_and_vulnerability_crud(self):
        scan_id = ScanModel.create_scan("http://127.0.0.1:3000")
        self.assertIsNotNone(scan_id)

        scan = ScanModel.get_scan(scan_id)
        self.assertEqual(scan['target_url'], "http://127.0.0.1:3000")
        self.assertEqual(scan['status'], "pending")

        vuln_id = VulnerabilityModel.create_vulnerability(
            scan_id=scan_id,
            name="Test Vulnerability",
            severity="HIGH",
            description="Test Desc",
            evidence="Test Evidence",
            remediation="Test Remediation"
        )
        self.assertIsNotNone(vuln_id)

        ScanModel.update_scan_status(scan_id, "completed", total_vulnerabilities=1)
        updated_scan = ScanModel.get_scan(scan_id)
        self.assertEqual(updated_scan['status'], "completed")
        self.assertEqual(updated_scan['total_vulnerabilities'], 1)

        vulns = VulnerabilityModel.get_vulnerabilities_by_scan(scan_id)
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0]['name'], "Test Vulnerability")

        ScanModel.delete_scan(scan_id)
        self.assertIsNone(ScanModel.get_scan(scan_id))

if __name__ == '__main__':
    unittest.main()
