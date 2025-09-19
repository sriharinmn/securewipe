
import unittest
import tempfile
import os
from core.wiper import DataWiper
from core.detector import DeviceDetector
from core.certificate import CertificateGenerator

class TestDataWiper(unittest.TestCase):
    """Test cases for data wiping functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.wiper = DataWiper()
        self.detector = DeviceDetector()
        self.cert_gen = CertificateGenerator()
        
        # Create temporary test file
        self.test_file = tempfile.NamedTemporaryFile(delete=False)
        self.test_file.write(b"Test data for wiping" * 1000)  # 20KB test file
        self.test_file.close()
    
    def tearDown(self):
        """Clean up test environment"""
        if os.path.exists(self.test_file.name):
            os.unlink(self.test_file.name)
    
    def test_device_detection(self):
        """Test device detection functionality"""
        devices = self.detector.get_all_devices()
        self.assertIsInstance(devices, list)
    
    def test_file_wipe_nist(self):
        """Test NIST method file wiping"""
        cert_id = self.wiper.wipe_device(self.test_file.name, 'nist')
        self.assertIsNotNone(cert_id)
        
        # Verify file content is wiped
        with open(self.test_file.name, 'rb') as f:
            content = f.read()
            self.assertNotIn(b"Test data for wiping", content)
    
    def test_file_wipe_dod(self):
        """Test DoD method file wiping"""
        cert_id = self.wiper.wipe_device(self.test_file.name, 'dod')
        self.assertIsNotNone(cert_id)
    
    def test_certificate_generation(self):
        """Test certificate generation and verification"""
        from datetime import datetime
        
        test_data = {
            'device_path': '/dev/test',
            'device_size': 1024,
            'method': 'NIST',
            'start_time': datetime.now(),
            'end_time': datetime.now(),
            'duration': 60.0,
            'verification_hashes': [
                {'pass': 1, 'pattern': '00', 'hash': 'test_hash_1'},
                {'pass': 2, 'pattern': 'ff', 'hash': 'test_hash_2'}
            ],
            'passes': 2
        }
        
        cert_id = self.cert_gen.generate_certificate(test_data)
        self.assertIsNotNone(cert_id)
        
        # Test certificate verification
        cert_path = os.path.join(self.cert_gen.cert_dir, f'{cert_id}.json')
        valid, message = self.cert_gen.verify_certificate(cert_path)
        self.assertTrue(valid)

if __name__ == '__main__':
    unittest.main()