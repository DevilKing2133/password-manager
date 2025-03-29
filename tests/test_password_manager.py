import os
import unittest
from password_manager import PasswordManager
import tempfile

class TestPasswordManager(unittest.TestCase):
    def setUp(self):
        self.data_file = tempfile.NamedTemporaryFile(delete=False)
        self.key_file = tempfile.NamedTemporaryFile(delete=False)
        self.pm = PasswordManager(self.data_file.name, self.key_file.name)
        self.master_password = "supersecret123"
        self.test_service = "test_service"
        self.test_username = "test_user"
        self.test_password = "test_password123"

    def tearDown(self):
        self.data_file.close()
        self.key_file.close()
        os.unlink(self.data_file.name)
        os.unlink(self.key_file.name)

    def test_save_and_retrieve_password(self):
        # Save a password
        self.pm.save_password(
            self.test_service,
            self.test_username,
            self.test_password,
            self.master_password
        )

        # Retrieve the password
        entry = self.pm.get_password(self.test_service, self.master_password)

        self.assertEqual(entry['username'], self.test_username)
        self.assertEqual(entry['password'], self.test_password)

    def test_list_services(self):
        # Save a password
        self.pm.save_password(
            self.test_service,
            self.test_username,
            self.test_password,
            self.master_password
        )

        # List services
        services = self.pm.list_services(self.master_password)

        self.assertIn(self.test_service, services)

    def test_wrong_master_password(self):
        # Save a password
        self.pm.save_password(
            self.test_service,
            self.test_username,
            self.test_password,
            self.master_password
        )

        # Try to retrieve with wrong password
        with self.assertRaises(Exception):
            self.pm.get_password(self.test_service, "wrongpassword")

if __name__ == '__main__':
    unittest.main()