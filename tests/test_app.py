"""Workflow tests for registration, authentication, and account access."""

import os
import secrets
import shutil
import tempfile
import unittest

from app import create_app

TEST_CREDENTIAL = "Chocolate8" + "!Secure"


class MemoryVault:
    """Keep test password hashes in memory instead of the OS credential store."""

    def __init__(self):
        """Initialize an empty mapping of usernames to password hashes."""
        self.values = {}

    def set_hash(self, username, password_hash):
        """Save a test password hash for a normalized username."""
        self.values[username] = password_hash

    def get_hash(self, username):
        """Return the saved test hash, or ``None`` when absent."""
        return self.values.get(username)


class AccountFlowTests(unittest.TestCase):
    """Exercise the member registration, sign-in, and dashboard flows."""

    def setUp(self):
        """Create an isolated app, database, and fake credential vault."""
        self.temp_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.temp_dir)
        self.vault = MemoryVault()
        self.app = create_app(
            {
                "TESTING": True,
                "WTF_CSRF_ENABLED": False,
                "RATELIMIT_ENABLED": False,
                "SECRET_KEY": secrets.token_hex(32),
                "DATABASE": os.path.join(self.temp_dir, "test.sqlite3"),
            },
            credential_vault=self.vault,
        )
        self.client = self.app.test_client()

    def test_register_sign_in_and_view_accounts(self):
        """Register, authenticate, and verify both account types are visible."""
        response = self.client.post(
            "/register",
            data={
                "email": "member@example.com",
                "username": "MemberUser8",
                "password": TEST_CREDENTIAL,
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(len(self.vault.values), 1)

        response = self.client.post(
            "/login", data={"username": "MemberUser8", "password": TEST_CREDENTIAL}
        )
        self.assertEqual(response.status_code, 302)
        response = self.client.get("/home")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Chocolate Lovers Federal Credit Union", response.data)
        self.assertIn(b"Checking", response.data)
        self.assertIn(b"Savings", response.data)
        self.assertIn(b"123456789", response.data)

    def test_rejects_each_invalid_registration_field(self):
        """Reject invalid email, username, password, and injection-shaped input."""
        valid_data = {
            "email": "member@example.com",
            "username": "MemberUser8",
            "password": TEST_CREDENTIAL,
        }
        invalid_variants = (
            ("email", "not-an-email"),
            ("username", "Abc1234"),
            ("username", "lowercase8"),
            ("username", "UpperCase"),
            ("username", "Member8' OR '1'='1"),
            ("password", "Short8!Aa"),
            ("password", "lowercase123!long"),
            ("password", "Uppercase!!!long"),
            ("password", "Uppercase123long"),
        )
        for field, value in invalid_variants:
            with self.subTest(field=field, value=value):
                response = self.client.post(
                    "/register", data={**valid_data, field: value}
                )
                self.assertEqual(response.status_code, 400)
                self.assertEqual(self.vault.values, {})

    def test_duplicate_username_is_rejected(self):
        """Reject a second registration that reuses an existing username."""
        data = {
            "email": "member@example.com",
            "username": "MemberUser8",
            "password": TEST_CREDENTIAL,
        }
        self.client.post("/register", data=data)
        response = self.client.post(
            "/register",
            data={**data, "email": "other@example.com"},
        )
        self.assertEqual(response.status_code, 409)

    def test_home_requires_authentication(self):
        """Redirect anonymous visitors away from the private dashboard."""
        response = self.client.get("/home")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])


if __name__ == "__main__":
    unittest.main()
