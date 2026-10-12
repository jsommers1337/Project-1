"""Local demo banking portal with OS-backed credential storage."""

import os
import re
import secrets
import sqlite3
from datetime import timedelta
from functools import wraps

from email_validator import EmailNotValidError, validate_email
import keyring
import secretstorage
from flask import (
    Flask,
    abort,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash


INSTITUTION = "Chocolate Lovers Federal Credit Union"
ROUTING_NUMBER = "123456789"
VAULT_SERVICE = "Chocolate Lovers Federal Credit Union"
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{8,32}$")
SPECIAL_PATTERN = re.compile(r"[^A-Za-z0-9]")


class CredentialStoreUnavailable(RuntimeError):
    """Signal that the operating system credential store cannot be used."""


class PasswordVault:
    """Store password hashes in Secret Service, or Windows Credential Manager."""

    @staticmethod
    def _windows_backend():
        """Return the active Windows Credential Manager keyring backend."""
        backend = keyring.get_keyring()
        if "windows" not in type(backend).__module__.lower():
            raise CredentialStoreUnavailable("Windows Credential Manager is unavailable.")
        return backend

    @staticmethod
    def _secret_service_collection():
        """Return the unlocked default Secret Service collection."""
        bus = secretstorage.dbus_init()
        collection = secretstorage.get_default_collection(bus)
        if collection.is_locked():
            raise CredentialStoreUnavailable("Unlock the desktop Secret Service and try again.")
        return collection

    def set_hash(self, username, password_hash):
        """Save one user's salted password hash in the OS credential store."""
        key = username.casefold()
        try:
            if os.name == "nt":
                self._windows_backend().set_password(VAULT_SERVICE, key, password_hash)
                return
            collection = self._secret_service_collection()
            collection.create_item(
                f"{VAULT_SERVICE} password hash for {key}",
                {"application": VAULT_SERVICE, "username": key},
                password_hash.encode("utf-8"),
                replace=True,
            )
        except CredentialStoreUnavailable:
            raise
        except Exception as error:
            raise CredentialStoreUnavailable(
                "The operating system credential store is unavailable."
            ) from error

    def get_hash(self, username):
        """Return a user's stored password hash, or ``None`` when absent."""
        key = username.casefold()
        try:
            if os.name == "nt":
                return self._windows_backend().get_password(VAULT_SERVICE, key)
            collection = self._secret_service_collection()
            for item in collection.search_items({"application": VAULT_SERVICE, "username": key}):
                return item.get_secret().decode("utf-8")
            return None
        except CredentialStoreUnavailable:
            raise
        except Exception as error:
            raise CredentialStoreUnavailable(
                "The operating system credential store is unavailable."
            ) from error


def get_db():
    """Return the current request's SQLite connection."""
    if "db" not in g:
        g.db = sqlite3.connect(current_app_config()["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def current_app_config():
    """Return the configuration mapping for the active Flask app."""
    return current_app.config


def close_db(_error=None):
    """Close the request-scoped SQLite connection when one exists."""
    database = g.pop("db", None)
    if database is not None:
        database.close()


def init_db():
    """Create the user and account tables if they do not already exist."""
    database_path = current_app_config()["DATABASE"]
    os.makedirs(os.path.dirname(database_path), exist_ok=True)
    database = sqlite3.connect(database_path)
    database.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            email TEXT NOT NULL,
            email_norm TEXT NOT NULL UNIQUE,
            username TEXT NOT NULL,
            username_norm TEXT NOT NULL UNIQUE
        );
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            account_type TEXT NOT NULL CHECK (account_type IN ('Checking', 'Savings')),
            account_number TEXT NOT NULL UNIQUE,
            routing_number TEXT NOT NULL
        );
        """
    )
    database.close()


def valid_registration(email, username, password):
    """Validate registration fields and return the normalized email address."""
    if not isinstance(email, str) or len(email) > 254:
        return False, "Enter a valid email address."
    username_error = "Username must be 8–32 characters, with a capital letter and a number."
    if (
        not isinstance(username, str)
        or not USERNAME_PATTERN.fullmatch(username)
        or not any(character.isupper() for character in username)
        or not any(character.isdigit() for character in username)
    ):
        return False, username_error
    requirements_message = (
        "Use at least 12 characters, with a capital letter, "
        "a number, and a special character."
    )
    if not isinstance(password, str) or len(password) < 12 or len(password) > 1024:
        return False, requirements_message
    password_requirements = (
        any(character.isupper() for character in password),
        any(character.isdigit() for character in password),
        bool(SPECIAL_PATTERN.search(password)),
    )
    if not all(password_requirements):
        return False, requirements_message
    try:
        normalized_email = validate_email(email.strip(), check_deliverability=False).normalized
    except EmailNotValidError:
        return False, "Enter a valid email address."
    return True, normalized_email


def login_required(view):
    """Redirect unauthenticated visitors to the sign-in page."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def make_account_number():
    """Generate a cryptographically random 12-digit account number."""
    return f"{secrets.randbelow(10**12):012d}"


def _register_security_headers(app):
    """Attach baseline browser security headers to app responses."""
    @app.after_request
    def security_headers(response):
        """Set browser protections on every response."""
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; form-action 'self'; "
            "frame-ancestors 'none'; base-uri 'self'; object-src 'none'"
        )
        return response


def _register_index_route(app):
    """Register the root route and redirect to the correct member page."""
    @app.route("/")
    def index():
        """Send signed-in members home and others to sign in."""
        endpoint = "dashboard" if "user_id" in session else "login"
        return redirect(url_for(endpoint))


def _register_registration_route(app, limiter):
    """Register the account-creation endpoint and its validation flow."""
    @app.route("/register", methods=["GET", "POST"])
    @limiter.limit("5 per hour")
    def register():
        """Create a member profile and its checking and savings accounts."""
        if request.method == "POST":
            email = request.form.get("email", "")
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            valid, result = valid_registration(email, username, password)
            if not valid:
                flash(result, "error")
                return render_template("register.html", email=email, username=username), 400

            normalized_email = result
            username_norm = username.casefold()
            database = get_db()
            try:
                database.execute("BEGIN IMMEDIATE")
                duplicate = database.execute(
                    "SELECT 1 FROM users WHERE email_norm = ? OR username_norm = ?",
                    (normalized_email.casefold(), username_norm),
                ).fetchone()
                if duplicate:
                    database.rollback()
                    flash("That email address or username is already registered.", "error")
                    return (
                        render_template("register.html", email=email, username=username),
                        409,
                    )

                credential_hash = generate_password_hash(password)
                app.extensions["credential_vault"].set_hash(username_norm, credential_hash)
                cursor = database.execute(
                    "INSERT INTO users (email, email_norm, username, username_norm) "
                    "VALUES (?, ?, ?, ?)",
                    (normalized_email, normalized_email.casefold(), username, username_norm),
                )
                user_id = cursor.lastrowid
                account_numbers = {make_account_number(), make_account_number()}
                while len(account_numbers) < 2:
                    account_numbers.add(make_account_number())
                for account_type, account_number in zip(
                    ("Checking", "Savings"), account_numbers
                ):
                    database.execute(
                        "INSERT INTO accounts "
                        "(user_id, account_type, account_number, routing_number) "
                        "VALUES (?, ?, ?, ?)",
                        (user_id, account_type, account_number, ROUTING_NUMBER),
                    )
                database.commit()
            except CredentialStoreUnavailable:
                database.rollback()
                flash("Secure credential storage is unavailable on this device.", "error")
                return render_template("register.html", email=email, username=username), 503
            except sqlite3.IntegrityError:
                database.rollback()
                flash("That email address or username is already registered.", "error")
                return render_template("register.html", email=email, username=username), 409
            except Exception:
                database.rollback()
                raise

            flash("Your account is ready. Sign in to continue.", "success")
            return redirect(url_for("login"))

        return render_template("register.html", email="", username="")


def _register_login_route(app, limiter):
    """Register the sign-in endpoint and authentication flow."""
    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("10 per minute")
    def login():
        """Authenticate a member and start a protected session."""
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            if (
                not isinstance(username, str)
                or len(username) > 32
                or not isinstance(password, str)
                or len(password) > 1024
            ):
                flash("Username or password is incorrect.", "error")
                return render_template("login.html", username=""), 400
            user = get_db().execute(
                "SELECT id, username, username_norm FROM users WHERE username_norm = ?",
                (username.casefold(),),
            ).fetchone()
            try:
                stored_hash = (
                    app.extensions["credential_vault"].get_hash(username.casefold())
                    if user
                    else None
                )
            except CredentialStoreUnavailable:
                flash("Secure credential storage is unavailable on this device.", "error")
                return render_template("login.html", username=username), 503
            if user and stored_hash and check_password_hash(stored_hash, password):
                session.clear()
                session.permanent = True
                session["user_id"] = user["id"]
                return redirect(url_for("dashboard"))
            flash("Username or password is incorrect.", "error")
            return render_template("login.html", username=username), 401

        return render_template("login.html", username="")


def _register_dashboard_route(app):
    """Register the authenticated member dashboard endpoint."""
    @app.route("/home")
    @login_required
    def dashboard():
        """Display the member profile and linked account details."""
        user = get_db().execute(
            "SELECT email, username FROM users WHERE id = ?", (session["user_id"],)
        ).fetchone()
        if user is None:
            session.clear()
            abort(401)
        accounts = get_db().execute(
            "SELECT account_type, account_number, routing_number "
            "FROM accounts WHERE user_id = ? ORDER BY account_type",
            (session["user_id"],),
        ).fetchall()
        return render_template(
            "dashboard.html", user=user, accounts=accounts, institution=INSTITUTION
        )


def _register_logout_route(app):
    """Register the sign-out endpoint."""
    @app.route("/logout", methods=["POST"])
    def logout():
        """Clear the current session and return to sign in."""
        session.clear()
        return redirect(url_for("login"))


def create_app(test_config=None, credential_vault=None):
    """Build and configure the Flask application instance."""
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32),
        DATABASE=os.environ.get("DATABASE_PATH")
        or os.path.join(app.instance_path, "accounts.sqlite3"),
        MAX_CONTENT_LENGTH=16 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        RATELIMIT_STORAGE_URI="memory://",
    )
    if test_config:
        app.config.update(test_config)

    app.extensions["credential_vault"] = credential_vault or PasswordVault()
    CSRFProtect(app)
    limiter = Limiter(get_remote_address, app=app, default_limits=[])
    app.extensions["limiter"] = limiter
    app.teardown_appcontext(close_db)

    with app.app_context():
        init_db()

    _register_security_headers(app)
    _register_index_route(app)
    _register_registration_route(app, limiter)
    _register_login_route(app, limiter)
    _register_dashboard_route(app)
    _register_logout_route(app)
    return app


application = create_app()


if __name__ == "__main__":
    application.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
