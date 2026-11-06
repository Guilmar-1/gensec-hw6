import unittest
from scanner.validator import URLValidator

class TestURLValidator(unittest.TestCase):
    def test_allowed_localhost(self):
        valid, msg = URLValidator.validate_url("http://127.0.0.1:3000")
        self.assertTrue(valid)

    def test_disallowed_external_ip(self):
        valid, msg = URLValidator.validate_url("http://8.8.8.8")
        self.assertFalse(valid)

    def test_invalid_scheme(self):
        valid, msg = URLValidator.validate_url("file:///etc/passwd")
        self.assertFalse(valid)

if __name__ == '__main__':
    unittest.main()
