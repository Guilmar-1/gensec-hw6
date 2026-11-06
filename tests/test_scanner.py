import unittest
from unittest.mock import patch
from scanner.modules.headers_check import HeadersCheckModule
from scanner.modules.sensitive_files import SensitiveFilesModule
from scanner.modules.sqli_check import SQLiCheckModule
from scanner.modules.xss_check import XSSCheckModule

class TestScannerModules(unittest.TestCase):
    @patch('scanner.modules.headers_check.SafeHTTPClient.request')
    def test_headers_check_missing_headers(self, mock_request):
        mock_request.return_value = (200, {}, "<html></html>")
        module = HeadersCheckModule()
        findings = module.run("http://127.0.0.1:3000")
        
        finding_names = [f['name'] for f in findings]
        self.assertTrue(any("x-frame-options" in name for name in finding_names))
        self.assertTrue(any("x-content-type-options" in name for name in finding_names))

    @patch('scanner.modules.sensitive_files.SafeHTTPClient.request')
    def test_sensitive_files_detection(self, mock_request):
        def side_effect(url, method="GET"):
            if ".env" in url:
                return (200, {}, "DB_PASSWORD=secret")
            return (404, {}, "Not found")

        mock_request.side_effect = side_effect
        module = SensitiveFilesModule()
        findings = module.run("http://127.0.0.1:3000")
        
        self.assertEqual(len(findings), 1)
        self.assertIn("Exposed Sensitive Path: /.env", findings[0]['name'])

    @patch('scanner.modules.sqli_check.SafeHTTPClient.request')
    def test_sqli_check_detection(self, mock_request):
        mock_request.return_value = (500, {}, "sqlite3.OperationalError: near syntax error")
        module = SQLiCheckModule()
        findings = module.run("http://127.0.0.1:3000?id=1")
        
        self.assertEqual(len(findings), 1)
        self.assertIn("Potential SQL Injection in parameter 'id'", findings[0]['name'])

    @patch('scanner.modules.xss_check.SafeHTTPClient.request')
    def test_xss_check_detection(self, mock_request):
        mock_request.return_value = (200, {}, "<html><body><SecScanXSSProbeTest></body></html>")
        module = XSSCheckModule()
        findings = module.run("http://127.0.0.1:3000?q=test")
        
        self.assertEqual(len(findings), 1)
        self.assertIn("Reflected XSS in parameter 'q'", findings[0]['name'])

if __name__ == '__main__':
    unittest.main()
