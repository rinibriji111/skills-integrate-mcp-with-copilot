import hashlib
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app


class TeacherAuthTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.credentials_file = Path(self.temp_dir.name) / "teachers.json"
        self.password = "test-password"
        self.iterations = 310_000
        self.salt = b"test-salt-for-auth"
        digest = hashlib.pbkdf2_hmac(
            "sha256", self.password.encode(), self.salt, self.iterations
        ).hex()
        self.credentials_file.write_text(
            json.dumps(
                {
                    "teachers": [
                        {
                            "username": "teacher@example.edu",
                            "password_hash": (
                                f"pbkdf2_sha256${self.iterations}${self.salt.hex()}${digest}"
                            ),
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        self.credentials_patch = patch.object(app, "TEACHERS_FILE", self.credentials_file)
        self.credentials_patch.start()

    def tearDown(self):
        self.credentials_patch.stop()
        self.temp_dir.cleanup()
        app.teacher_sessions.clear()

    def test_teacher_password_is_verified_from_json(self):
        self.assertTrue(app.is_valid_teacher("teacher@example.edu", self.password))
        self.assertFalse(app.is_valid_teacher("teacher@example.edu", "wrong-password"))
        self.assertFalse(app.is_valid_teacher("student@example.edu", self.password))

    def test_session_requires_valid_unexpired_cookie(self):
        with self.assertRaises(app.HTTPException) as missing_session:
            app.require_teacher()
        self.assertEqual(missing_session.exception.status_code, 401)

        app.teacher_sessions["valid-session"] = (
            "teacher@example.edu",
            time.time() + 60,
        )
        self.assertEqual(app.require_teacher("valid-session"), "teacher@example.edu")

        app.teacher_sessions["expired-session"] = (
            "teacher@example.edu",
            time.time() - 1,
        )
        with self.assertRaises(app.HTTPException) as expired_session:
            app.require_teacher("expired-session")
        self.assertEqual(expired_session.exception.status_code, 401)

    def test_activity_mutations_require_teacher_but_listing_is_public(self):
        signup_route = next(
            route
            for route in app.app.routes
            if getattr(route, "path", None) == "/activities/{activity_name}/signup"
        )
        unregister_route = next(
            route
            for route in app.app.routes
            if getattr(route, "path", None) == "/activities/{activity_name}/unregister"
        )
        activities_route = next(
            route
            for route in app.app.routes
            if getattr(route, "path", None) == "/activities"
        )

        for route in (signup_route, unregister_route):
            dependencies = [dependency.call for dependency in route.dependant.dependencies]
            self.assertIn(app.require_teacher, dependencies)
        self.assertEqual(activities_route.dependant.dependencies, [])


if __name__ == "__main__":
    unittest.main()