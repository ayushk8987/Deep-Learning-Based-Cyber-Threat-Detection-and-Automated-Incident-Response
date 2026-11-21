import unittest
import json
from app import app, RFC_5322_EMAIL_REGEX, validate_password_criteria
from src.database import init_db, authenticate_user

class TestAuthenticationValidation(unittest.TestCase):
    """
    AUTH VALIDATION: Comprehensive verification of email RFC 5322 compliance
    and the 5-point password security rules.
    """
    def setUp(self):
        init_db()
        self.client = app.test_client()

    def test_rfc5322_email_validation(self):
        # Valid RFC 5322 emails
        valid_emails = [
            "analyst@soc.local",
            "user.name@domain.com",
            "first.last+tag@sub.domain.org",
            "security_ops@enterprise.io"
        ]
        for email in valid_emails:
            self.assertTrue(bool(RFC_5322_EMAIL_REGEX.match(email)), f"Should be valid: {email}")

        # Invalid emails
        invalid_emails = [
            "plainaddress",
            "@missingusername.com",
            "username@.com",
            "username@com",
            "username@domain..com",
            "spaces in@address.com"
        ]
        for email in invalid_emails:
            self.assertFalse(bool(RFC_5322_EMAIL_REGEX.match(email)), f"Should be invalid: {email}")

    def test_password_criteria_rules(self):
        # 1. Less than 8 characters
        res = validate_password_criteria("Sh0rt!")
        self.assertFalse(res["minLength"])

        # 2. No uppercase
        res = validate_password_criteria("lowercase123!")
        self.assertFalse(res["uppercase"])

        # 3. No lowercase
        res = validate_password_criteria("UPPERCASE123!")
        self.assertFalse(res["lowercase"])

        # 4. No number
        res = validate_password_criteria("NoNumbersHere!")
        self.assertFalse(res["number"])

        # 5. No special character
        res = validate_password_criteria("NoSpecialChars123")
        self.assertFalse(res["special"])

        # Fully valid password meeting all 5 rules
        res = validate_password_criteria("Secure@SOC2026!")
        self.assertTrue(all(res.values()), "Secure@SOC2026! should meet all 5 criteria")

    def test_api_auth_login_endpoints(self):
        # Empty email
        resp = self.client.post("/api/auth/login", json={"email": "", "password": "Secure@SOC2026!"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Please enter your email address", resp.get_json()["error"])

        # Invalid email format
        resp = self.client.post("/api/auth/login", json={"email": "not-an-email", "password": "Secure@SOC2026!"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("RFC 5322", resp.get_json()["error"])

        # Password rule failure
        resp = self.client.post("/api/auth/login", json={"email": "analyst@soc.local", "password": "weak"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Password requirement not met", resp.get_json()["error"])

        # Incorrect credentials
        resp = self.client.post("/api/auth/login", json={"email": "analyst@soc.local", "password": "WrongPassword@123"})
        self.assertEqual(resp.status_code, 401)
        self.assertIn("Unable to sign in", resp.get_json()["error"])

        # Successful authentication with default seeded analyst
        resp = self.client.post("/api/auth/login", json={"email": "analyst@soc.local", "password": "Secure@SOC2026!"})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["user"]["email"], "analyst@soc.local")

    def test_auth_status_and_logout(self):
        # Check initial status (unauthenticated)
        resp = self.client.get("/api/auth/status")
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.get_json()["authenticated"])

        # Login
        self.client.post("/api/auth/login", json={"email": "analyst@soc.local", "password": "Secure@SOC2026!"})

        # Check authenticated status
        resp = self.client.get("/api/auth/status")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.get_json()["authenticated"])

        # Logout
        resp = self.client.post("/api/auth/logout")
        self.assertEqual(resp.status_code, 200)

        # Check post-logout status
        resp = self.client.get("/api/auth/status")
        self.assertFalse(resp.get_json()["authenticated"])

if __name__ == "__main__":
    unittest.main()
