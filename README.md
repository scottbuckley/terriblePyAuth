> [!WARNING]
> For educational use only.

# excellent-pyauth

`excellent-pyauth` is a Flask authentication extension backed by SQLite.

## Install

```bash
python3 -m pip install -e .
```

## Configure

The SQLite file must already exist. The `users` and `sessions` tables do not
need to exist; the extension creates them on the first HTTP request or direct
authentication API call.

```bash
touch classroom.db
```

```python
from flask import Flask
from pyauth import PasswordRule, WebAuth

app = Flask(__name__)
auth = WebAuth(
    "classroom.db",
    password_rules=[
        PasswordRule(
            check=lambda password: len(password) >= 12,
            message="Password must contain at least 12 characters.",
        ),
        PasswordRule(
            check=lambda password: any(character.isupper() for character in password),
            message="Password must contain an uppercase character.",
        ),
    ],
)
auth.init_app(app)


@app.get("/account")
@auth.login_required
def account():
    return f"Hello, {auth.current_user.username}"


@app.get("/admin")
@auth.admin_required
def admin():
    return "Administrator area"
```

The extension installs these routes:

- `GET|POST /auth/login`
- `GET|POST /auth/register`
- `GET|POST /auth/logout`
- `POST /auth/check-password`

`auth.login_form()` and `auth.registration_form()` return standalone HTML form
snippets for applications that want to compose their own pages.

## Password policies

Pass an ordered list of `PasswordRule` objects to `WebAuth`. Each rule contains
a predicate and the message returned when that predicate fails. Rules are
checked from start to finish, and checking stops at the first failure.

The registration form checks the policy as the password is edited and displays
only the first failing rule. The registration endpoint also enforces the policy
server-side. Direct calls to `auth.create_user()` enforce it by default and
raise `PasswordPolicyError` when a rule fails, but trusted callers can opt out:

```python
auth.create_user(
    "imported-user",
    "legacy-password",
    enforce_password_policy=False,
)
```

## Sessions

This package does not use Flask's cookie-based session system. Successful login
inserts a row into `sessions`, then places its integer ID in the
`pyauth_session` cookie. Each authenticated request joins that session row to
its user row. Logout deletes the server-side row and clears the cookie.

The supplied database file is opened in SQLite `mode=rw`, so a typo in its path
raises `FileNotFoundError` rather than silently creating another database.

The tables can be inspected directly:

```bash
sqlite3 classroom.db "SELECT * FROM users;"
sqlite3 classroom.db "SELECT * FROM sessions;"
```

`CREATE TABLE IF NOT EXISTS` preserves compatible existing tables and their
data. It does not migrate an incompatible schema.

## Run tests

```bash
python3 -m unittest discover -s tests -v
```
