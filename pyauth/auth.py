"""Flask authentication backed by SQLite."""

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from functools import wraps
from html import escape
from pathlib import Path
import sqlite3
from threading import Lock
from typing import Any, TypeVar, cast

from flask import Blueprint, Flask, abort, g, make_response, redirect, request
from markupsafe import Markup


@dataclass(frozen=True, slots=True)
class User:
    id: int
    username: str
    is_admin: bool


@dataclass(frozen=True, slots=True)
class PasswordRule:
    """A password predicate and the message shown when it returns false."""

    check: Callable[[str], bool]
    message: str


class PasswordPolicyError(ValueError):
    """Raised when a password fails the configured policy."""


View = TypeVar("View", bound=Callable[..., Any])


class WebAuth:
    """Add SQLite authentication to a Flask app."""

    def __init__(
        self,
        database: str | Path,
        *,
        url_prefix: str = "/auth",
        cookie_name: str = "pyauth_session",
        login_redirect: str = "/",
        password_rules: Sequence[PasswordRule] | None = None,
    ) -> None:
        self.database = Path(database).expanduser().resolve()
        if not self.database.is_file():
            raise FileNotFoundError(
                f"The SQLite database must already exist: {self.database}"
            )

        self.url_prefix = "/" + url_prefix.strip("/")
        self.cookie_name = cookie_name
        self.login_redirect = login_redirect
        self.password_rules = tuple(password_rules or ())
        self._schema_ready = False
        self._schema_lock = Lock()

        self.blueprint = Blueprint("pyauth", __name__)
        self.blueprint.add_url_rule(
            "/login", "login", self._login_view, methods=["GET", "POST"]
        )
        self.blueprint.add_url_rule(
            "/register", "register", self._register_view, methods=["GET", "POST"]
        )
        self.blueprint.add_url_rule(
            "/check-password",
            "check_password",
            self._check_password_view,
            methods=["POST"],
        )
        self.blueprint.add_url_rule(
            "/logout", "logout", self._logout_view, methods=["GET", "POST"]
        )

    def init_app(self, app: Flask) -> None:
        """Register authentication routes and lazy schema setup."""
        if "pyauth" in app.extensions:
            raise RuntimeError("A WebAuth instance is already registered")
        app.extensions["pyauth"] = self
        app.before_request(self._ensure_schema)
        app.register_blueprint(self.blueprint, url_prefix=self.url_prefix)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(f"{self.database.as_uri()}?mode=rw", uri=True)
        connection.row_factory = sqlite3.Row
        return connection

    def _ensure_schema(self) -> None:
        if self._schema_ready:
            return

        with self._schema_lock:
            if self._schema_ready:
                return
            with self._connect() as connection:
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL UNIQUE,
                        password TEXT NOT NULL,
                        is_admin INTEGER NOT NULL DEFAULT 0
                    );

                    CREATE TABLE IF NOT EXISTS sessions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        expires_at TEXT
                    );
                    """
                )
            self._schema_ready = True

    def create_user(
        self,
        username: str,
        password: str,
        *,
        is_admin: bool = False,
        enforce_password_policy: bool = True,
    ) -> User:
        """Create a user, optionally bypassing the configured password policy."""
        if enforce_password_policy:
            failure = self.check_password(password)
            if failure is not None:
                raise PasswordPolicyError(failure)

        self._ensure_schema()
        with self._connect() as connection:
            cursor = connection.execute(
                "INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
                (username, password, int(is_admin)),
            )
            user_id = cursor.lastrowid

        if user_id is None:
            raise RuntimeError("SQLite did not return a user id")
        return User(user_id, username, bool(is_admin))

    def check_password(self, password: str) -> str | None:
        """Return the first failing rule's message, or None if all rules pass."""
        for rule in self.password_rules:
            if not rule.check(password):
                return rule.message
        return None

    def authenticate(self, username: str, password: str) -> User | None:
        """Check user credentials."""
        self._ensure_schema()
        query = (
            "SELECT id, username, is_admin FROM users "
            f"WHERE username = '{username}' AND password = '{password}'"
        )
        with self._connect() as connection:
            row = connection.execute(query).fetchone()
        return self._row_to_user(row)

    @property
    def current_user(self) -> User | None:
        """Return the user identified by this request's session cookie."""
        if "pyauth_user" not in g:
            session_id = request.cookies.get(self.cookie_name)
            g.pyauth_user = self._user_from_session(session_id)
        return cast(User | None, g.pyauth_user)

    def login_required(self, view: View) -> View:
        @wraps(view)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            if self.current_user is None:
                return redirect(f"{self.url_prefix}/login")
            return view(*args, **kwargs)

        return cast(View, wrapped)

    def admin_required(self, view: View) -> View:
        @wraps(view)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            user = self.current_user
            if user is None:
                return redirect(f"{self.url_prefix}/login")
            if not user.is_admin:
                abort(403)
            return view(*args, **kwargs)

        return cast(View, wrapped)

    def login_form(self, error: str | None = None) -> Markup:
        """Return a standalone login form HTML snippet."""
        message = f'<p role="alert">{escape(error)}</p>' if error else ""
        action = escape(f"{self.url_prefix}/login", quote=True)
        return Markup(
            f"""{message}<form method="post" action="{action}">
  <label for="pyauth-username">Username</label>
  <input id="pyauth-username" name="username" autocomplete="username" required>
  <label for="pyauth-password">Password</label>
  <input id="pyauth-password" name="password" type="password" autocomplete="current-password" required>
  <button type="submit">Log in</button>
</form>"""
        )

    def registration_form(self, error: str | None = None) -> Markup:
        """Return a standalone registration form HTML snippet."""
        message = f'<p role="alert">{escape(error)}</p>' if error else ""
        action = escape(f"{self.url_prefix}/register", quote=True)
        policy_action = escape(f"{self.url_prefix}/check-password", quote=True)
        policy_script = ""
        if self.password_rules:
            policy_script = """
<script>
(() => {
  const form = document.getElementById("pyauth-registration-form");
  const password = document.getElementById("pyauth-new-password");
  const feedback = document.getElementById("pyauth-password-feedback");
  let controller;

  password.addEventListener("input", async () => {
    if (controller) controller.abort();
    controller = new AbortController();
    password.setCustomValidity("");
    feedback.textContent = "";

    try {
      const response = await fetch(form.dataset.passwordPolicyUrl, {
        method: "POST",
        headers: {"Content-Type": "application/x-www-form-urlencoded"},
        body: new URLSearchParams({password: password.value}),
        signal: controller.signal,
      });
      if (!response.ok) return;

      const result = await response.json();
      const failure = result.valid ? "" : result.message;
      password.setCustomValidity(failure);
      feedback.textContent = failure;
    } catch (error) {
      if (error.name !== "AbortError") throw error;
    }
  });
})();
</script>"""
        return Markup(
            f"""{message}<form id="pyauth-registration-form" method="post" action="{action}" data-password-policy-url="{policy_action}">
  <label for="pyauth-new-username">Username</label>
  <input id="pyauth-new-username" name="username" autocomplete="username" required>
  <label for="pyauth-new-password">Password</label>
  <input id="pyauth-new-password" name="password" type="password" autocomplete="new-password" required>
  <p id="pyauth-password-feedback" role="alert" aria-live="polite"></p>
  <label><input name="is_admin" type="checkbox" value="1"> Administrator</label>
  <button type="submit">Create account</button>
</form>{policy_script}"""
        )

    def _login_view(self) -> Any:
        if request.method == "GET":
            return self.login_form()

        user = self.authenticate(
            request.form.get("username", ""), request.form.get("password", "")
        )
        if user is None:
            return self.login_form("Invalid username or password"), 401

        session_id = self._create_session(user.id)
        response = make_response(redirect(self.login_redirect))
        response.set_cookie(
            self.cookie_name,
            str(session_id),
            httponly=False,
            secure=False,
            samesite=None,
        )
        return response

    def _register_view(self) -> Any:
        if request.method == "GET":
            return self.registration_form()

        try:
            self.create_user(
                request.form.get("username", ""),
                request.form.get("password", ""),
                is_admin="is_admin" in request.form,
                enforce_password_policy=True,
            )
        except PasswordPolicyError as error:
            return self.registration_form(str(error)), 400
        except sqlite3.IntegrityError:
            return self.registration_form("Username already exists"), 409
        return redirect(f"{self.url_prefix}/login")

    def _check_password_view(self) -> dict[str, str | bool]:
        failure = self.check_password(request.form.get("password", ""))
        return {
            "valid": failure is None,
            "message": failure or "",
        }

    def _logout_view(self) -> Any:
        session_id = request.cookies.get(self.cookie_name)
        if session_id is not None:
            with self._connect() as connection:
                connection.execute("DELETE FROM sessions WHERE id = ?", (session_id,))

        response = make_response(redirect(f"{self.url_prefix}/login"))
        response.delete_cookie(self.cookie_name)
        return response

    def _create_session(self, user_id: int) -> int:
        with self._connect() as connection:
            cursor = connection.execute(
                "INSERT INTO sessions (user_id) VALUES (?)", (user_id,)
            )
            session_id = cursor.lastrowid
        if session_id is None:
            raise RuntimeError("SQLite did not return a session id")
        return session_id

    def _user_from_session(self, session_id: str | None) -> User | None:
        if session_id is None:
            return None
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT users.id, users.username, users.is_admin
                FROM sessions
                JOIN users ON users.id = sessions.user_id
                WHERE sessions.id = ?
                """,
                (session_id,),
            ).fetchone()
        return self._row_to_user(row)

    @staticmethod
    def _row_to_user(row: sqlite3.Row | None) -> User | None:
        if row is None:
            return None
        return User(
            id=row["id"],
            username=row["username"],
            is_admin=bool(row["is_admin"]),
        )
