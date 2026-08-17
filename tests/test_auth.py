from http.cookies import SimpleCookie
from pathlib import Path
import sqlite3
import tempfile
import unittest

from flask import Flask

from pyauth import PasswordPolicyError, PasswordRule, WebAuth


class WebAuthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary_directory.name) / "existing.db"
        self.database.touch()

        self.app = Flask(__name__)
        self.app.config.update(TESTING=True)
        self.auth = WebAuth(self.database)
        self.auth.init_app(self.app)

        @self.app.get("/private")
        @self.auth.login_required
        def private() -> str:
            return self.auth.current_user.username

        @self.app.get("/admin")
        @self.auth.admin_required
        def admin() -> str:
            return "admin"

        self.client = self.app.test_client()

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_missing_database_is_not_created(self) -> None:
        missing = Path(self.temporary_directory.name) / "missing.db"

        with self.assertRaises(FileNotFoundError):
            WebAuth(missing)

        self.assertFalse(missing.exists())

    def test_first_request_creates_both_tables(self) -> None:
        with sqlite3.connect(self.database) as connection:
            before = connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        self.assertEqual(before, [])

        response = self.client.get("/auth/login")

        self.assertEqual(response.status_code, 200)
        with sqlite3.connect(self.database) as connection:
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
        self.assertIn("users", tables)
        self.assertIn("sessions", tables)

    def test_registration_accepts_admin_and_stores_plaintext_password(self) -> None:
        response = self.client.post(
            "/auth/register",
            data={"username": "teacher", "password": "visible", "is_admin": "1"},
        )

        self.assertEqual(response.status_code, 302)
        with sqlite3.connect(self.database) as connection:
            user = connection.execute(
                "SELECT username, password, is_admin FROM users"
            ).fetchone()
        self.assertEqual(user, ("teacher", "visible", 1))

    def test_login_creates_server_side_session_and_cookie(self) -> None:
        self.auth.create_user("alice", "password123")

        response = self.client.post(
            "/auth/login", data={"username": "alice", "password": "password123"}
        )

        self.assertEqual(response.status_code, 302)
        cookie = SimpleCookie(response.headers["Set-Cookie"])["pyauth_session"]
        self.assertEqual(cookie.value, "1")
        self.assertFalse(cookie["httponly"])
        self.assertFalse(cookie["secure"])
        self.assertFalse(cookie["samesite"])
        with sqlite3.connect(self.database) as connection:
            session = connection.execute(
                "SELECT id, user_id, expires_at FROM sessions"
            ).fetchone()
        self.assertEqual(session, (1, 1, None))
        self.assertEqual(self.client.get("/private").get_data(as_text=True), "alice")

    def test_sql_injection_logs_in_as_admin(self) -> None:
        self.auth.create_user("teacher", "secret", is_admin=True)

        response = self.client.post(
            "/auth/login",
            data={"username": "teacher' --", "password": "wrong"},
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.get("/admin").status_code, 200)

    def test_guessed_session_id_grants_admin_access(self) -> None:
        self.auth.create_user("teacher", "secret", is_admin=True)
        self.auth.create_user("alice", "password123")
        admin_client = self.app.test_client()
        attacker_client = self.app.test_client()

        admin_login = admin_client.post(
            "/auth/login", data={"username": "teacher", "password": "secret"}
        )
        attacker_login = attacker_client.post(
            "/auth/login", data={"username": "alice", "password": "password123"}
        )

        admin_cookie = SimpleCookie(admin_login.headers["Set-Cookie"])[
            "pyauth_session"
        ]
        attacker_cookie = SimpleCookie(attacker_login.headers["Set-Cookie"])[
            "pyauth_session"
        ]
        self.assertEqual((admin_cookie.value, attacker_cookie.value), ("1", "2"))

        attacker_client.set_cookie("pyauth_session", "1")
        self.assertEqual(attacker_client.get("/admin").status_code, 200)

    def test_logout_deletes_server_side_session(self) -> None:
        self.auth.create_user("alice", "password123")
        self.client.post(
            "/auth/login", data={"username": "alice", "password": "password123"}
        )

        response = self.client.post("/auth/logout")

        self.assertEqual(response.status_code, 302)
        with sqlite3.connect(self.database) as connection:
            count = connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        self.assertEqual(count, 0)
        self.assertEqual(self.client.get("/private").status_code, 302)

    def test_form_helpers_return_html_snippets(self) -> None:
        self.assertIn('<form method="post"', self.auth.login_form())
        self.assertIn('name="is_admin"', self.auth.registration_form())

    def test_password_rules_return_only_the_first_failure(self) -> None:
        rules = [
            PasswordRule(lambda password: len(password) >= 8, "Too short"),
            PasswordRule(lambda password: "!" in password, "Needs an exclamation"),
            PasswordRule(lambda password: password.endswith("7"), "Must end in 7"),
        ]
        auth = WebAuth(self.database, password_rules=rules)

        self.assertEqual(auth.check_password("short"), "Too short")
        self.assertEqual(auth.check_password("long-enough"), "Needs an exclamation")
        self.assertEqual(auth.check_password("long-enough!"), "Must end in 7")
        self.assertIsNone(auth.check_password("long-enough!7"))

    def test_create_user_can_bypass_password_rules(self) -> None:
        auth = WebAuth(
            self.database,
            password_rules=[PasswordRule(lambda password: password == "accepted", "No")],
        )

        with self.assertRaisesRegex(PasswordPolicyError, "No"):
            auth.create_user("alice", "rejected")

        user = auth.create_user(
            "alice", "rejected", enforce_password_policy=False
        )
        self.assertEqual(user.username, "alice")

        with sqlite3.connect(self.database) as connection:
            password = connection.execute(
                "SELECT password FROM users WHERE username = ?", ("alice",)
            ).fetchone()[0]
        self.assertEqual(password, "rejected")

    def test_registration_enforces_rules_and_exposes_live_checker(self) -> None:
        app = Flask("password-policy-test")
        app.config.update(TESTING=True)
        auth = WebAuth(
            self.database,
            password_rules=[
                PasswordRule(lambda password: len(password) >= 8, "Too short"),
                PasswordRule(lambda password: "!" in password, "Needs an exclamation"),
            ],
        )
        auth.init_app(app)
        client = app.test_client()

        form = client.get("/auth/register").get_data(as_text=True)
        self.assertIn('data-password-policy-url="/auth/check-password"', form)
        self.assertIn('password.addEventListener("input"', form)
        self.assertIn('aria-live="polite"', form)

        first_failure = client.post(
            "/auth/check-password", data={"password": "short"}
        )
        self.assertEqual(
            first_failure.get_json(), {"valid": False, "message": "Too short"}
        )

        second_failure = client.post(
            "/auth/check-password", data={"password": "long-enough"}
        )
        self.assertEqual(
            second_failure.get_json(),
            {"valid": False, "message": "Needs an exclamation"},
        )

        rejected = client.post(
            "/auth/register", data={"username": "alice", "password": "long-enough"}
        )
        self.assertEqual(rejected.status_code, 400)
        self.assertIn("Needs an exclamation", rejected.get_data(as_text=True))

        accepted = client.post(
            "/auth/register", data={"username": "alice", "password": "long-enough!"}
        )
        self.assertEqual(accepted.status_code, 302)


if __name__ == "__main__":
    unittest.main()
