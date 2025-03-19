import unittest
from src.security import SecurityManager

class TestSecurityManager(unittest.TestCase):
    def setUp(self):
        self.security_manager = SecurityManager()

    def test_hash_password(self):
        password = "testPassword123"
        hashed = self.security_manager.hash_password(password)
        self.assertTrue(self.security_manager.check_password(password, hashed))

    # Add more tests for encryption and decryption

if __name__ == "__main__":
    unittest.main()
