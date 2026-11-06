import unittest
import os
import tempfile
from app import create_app
from config import Config

class TestApplicationRoutes(unittest.TestCase):
    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp()
        Config.DATABASE = self.db_path
        
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()

    def tearDown(self):
        os.close(self.db_fd)
        os.remove(self.db_path)

    def test_dashboard_index(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Launch Security Scan", response.data)

    def test_start_scan_invalid_url(self):
        response = self.client.post('/scan/start', data={'target_url': 'http://8.8.8.8'}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Invalid scan target", response.data)

    def test_history_page(self):
        response = self.client.get('/scans')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Scan History", response.data)

if __name__ == '__main__':
    unittest.main()
