"""Test website: public landing page, sign-up, login, and an account page where each
user saves and reads back their own favourite sport and favourite car colour.

Settings come from environment variables that systemd loads from /etc/webapp.env.

Who sees what: every query on the account page uses the user id stored in the
signed session cookie, never an id sent by the browser, so a user can only ever
read or change their own row.

Logging: every login, sign-up, logout and refused form is written as one JSON line
to /var/log/webapp/auth.log, which the CloudWatch agent ships to CloudWatch Logs.
Passwords are never logged. (Every page request is logged by nginx, not here.)
"""
import hmac
import json
import logging
import os
import re
import secrets
from datetime import datetime, timezone
from functools import wraps
from logging.handlers import WatchedFileHandler

import boto3
import psycopg
from flask import Flask, abort, redirect, render_template_string, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

DB_HOST = os.environ["DB_HOST"]
DB_PORT = int(os.environ.get("DB_PORT", "5432"))
DB_NAME = os.environ["DB_NAME"]
DB_SECRET_ARN = os.environ["DB_SECRET_ARN"]
AWS_REGION = os.environ["AWS_REGION"]

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
MIN_PASSWORD = 8
MAX_FIELD = 50  # longest favourite sport / car colour we store

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # Set COOKIE_SECURE=1 in /etc/webapp.env once the site is served over HTTPS.
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE") == "1",
)

# nginx sits in front and passes the visitor's address in X-Forwarded-For.
# Trust exactly one proxy hop, so request.remote_addr is the real visitor IP.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)

_secrets = boto3.client("secretsmanager", region_name=AWS_REGION)

# --- Audit log ----------------------------------------------------------------

AUTH_LOG = os.environ.get("AUTH_LOG", "/var/log/webapp/auth.log")
auth_log = logging.getLogger("webapp.auth")
auth_log.setLevel(logging.INFO)
auth_log.propagate = False
try:
    # WatchedFileHandler reopens the file after logrotate moves it.
    _handler = WatchedFileHandler(AUTH_LOG)
except OSError:
    _handler = logging.StreamHandler()  # running somewhere without /var/log/webapp
_handler.setFormatter(logging.Formatter("%(message)s"))
auth_log.addHandler(_handler)


def log_event(event, username="", **extra):
    """Write one JSON line, e.g. {"event": "login_failure", "username": "bob", "ip": ...}."""
    auth_log.info(json.dumps({
        "time": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "event": event,
        "username": username[:64],
        "ip": request.remote_addr,
        "user_agent": request.headers.get("User-Agent", "")[:200],
        **extra,
    }))


def db():
    """Open a database connection. The credentials are read from Secrets Manager each
    time, because RDS rotates the managed password (every 7 days by default)."""
    creds = json.loads(_secrets.get_secret_value(SecretId=DB_SECRET_ARN)["SecretString"])
    return psycopg.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=creds["username"],
        password=creds["password"],
        sslmode="require",
        connect_timeout=5,
    )


def init_db():
    """Create the tables if they are missing. Safe to run on every start."""
    with db() as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS users (
                   id            SERIAL PRIMARY KEY,
                   username      TEXT UNIQUE NOT NULL,
                   password_hash TEXT NOT NULL,
                   created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
               )"""
        )
        # "Alice" and "alice" are the same account.
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower ON users (lower(username))"
        )
        # One row per user. Deleting a user deletes their preferences too.
        conn.execute(
            """CREATE TABLE IF NOT EXISTS preferences (
                   user_id        INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                   favorite_sport TEXT,
                   car_colour     TEXT,
                   updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
               )"""
        )


# --- CSRF protection for every POST ------------------------------------------

def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def check_csrf():
    if request.method == "POST":
        expected = session.get("csrf")
        sent = request.form.get("csrf", "")
        if not expected or not hmac.compare_digest(sent, expected):
            log_event("csrf_failure", session.get("user", ""), path=request.path)
            abort(400)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def start_session(user_id, username):
    session.clear()  # a fresh session on every login
    session["user_id"] = user_id
    session["user"] = username


# --- Pages ------------------------------------------------------------------

LAYOUT = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Test site</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font-family:system-ui,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1rem;line-height:1.5}
input,button{font:inherit;padding:.4rem .6rem;margin:.2rem 0}input[type=text],input[type=password]{width:100%;max-width:20rem}
.error{color:#b00}.ok{color:#070}dl{display:grid;grid-template-columns:max-content 1fr;gap:.3rem 1rem}dt{font-weight:600}
nav{margin-bottom:2rem}nav form{display:inline}</style>
</head><body>
<nav><a href="{{ url_for('landing') }}">Home</a>
{% if session.get('user_id') %} · <a href="{{ url_for('account') }}">My account</a> ·
  <form method="post" action="{{ url_for('logout') }}"><input type="hidden" name="csrf" value="{{ csrf_token() }}"><button type="submit">Log out</button></form>
{% else %} · <a href="{{ url_for('login') }}">Log in</a> · <a href="{{ url_for('signup') }}">Sign up</a>{% endif %}
</nav>
{% block body %}{% endblock %}</body></html>"""


def page(body):
    return LAYOUT.replace("{% block body %}{% endblock %}", body)


LANDING = page("""
<h1>Welcome to the test site</h1>
<p>Create an account to save your favourite sport and your favourite car colour.
Only you can see what you save.</p>
<p><a href="{{ url_for('signup') }}">Sign up</a> or <a href="{{ url_for('login') }}">log in</a>.</p>""")

SIGNUP = page("""
<h1>Sign up</h1>
{% if error %}<p class="error">{{ error }}</p>{% endif %}
<form method="post">
  <input type="hidden" name="csrf" value="{{ csrf_token() }}">
  <p><label>Username (3-32 letters, digits, . _ -)<br>
     <input type="text" name="username" value="{{ username }}" autocomplete="username" required></label></p>
  <p><label>Password (at least 8 characters)<br>
     <input type="password" name="password" autocomplete="new-password" required></label></p>
  <p><label>Password again<br>
     <input type="password" name="password2" autocomplete="new-password" required></label></p>
  <button type="submit">Create account</button>
</form>""")

LOGIN = page("""
<h1>Log in</h1>
{% if error %}<p class="error">{{ error }}</p>{% endif %}
<form method="post">
  <input type="hidden" name="csrf" value="{{ csrf_token() }}">
  <p><label>Username<br><input type="text" name="username" autocomplete="username" required></label></p>
  <p><label>Password<br><input type="password" name="password" autocomplete="current-password" required></label></p>
  <button type="submit">Log in</button>
</form>""")

ACCOUNT = page("""
<h1>Welcome {{ username }}</h1>
{% if saved %}<p class="ok">Saved.</p>{% endif %}
{% if error %}<p class="error">{{ error }}</p>{% endif %}

<h2>What we have stored for you</h2>
{% if prefs %}
<dl>
  <dt>Favourite sport</dt><dd>{{ prefs.sport or "(not set)" }}</dd>
  <dt>Favourite car colour</dt><dd>{{ prefs.colour or "(not set)" }}</dd>
  <dt>Last updated</dt><dd>{{ prefs.updated }}</dd>
</dl>
{% else %}
<p>Nothing yet.</p>
{% endif %}

<h2>Update</h2>
<form method="post">
  <input type="hidden" name="csrf" value="{{ csrf_token() }}">
  <p><label>Favourite sport<br>
     <input type="text" name="sport" maxlength="{{ max_field }}" value="{{ prefs.sport if prefs else '' }}"></label></p>
  <p><label>Favourite car colour<br>
     <input type="text" name="colour" maxlength="{{ max_field }}" list="colours" value="{{ prefs.colour if prefs else '' }}"></label>
     <datalist id="colours"><option>Black</option><option>White</option><option>Silver</option>
       <option>Red</option><option>Blue</option><option>Green</option><option>Yellow</option></datalist></p>
  <button type="submit">Save</button>
</form>""")


@app.get("/")
def landing():
    return render_template_string(LANDING)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    error = None
    username = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        reason = None
        if not USERNAME_RE.fullmatch(username):
            error = "Username must be 3-32 letters, digits, dots, underscores or hyphens."
            reason = "bad_username"
        elif len(password) < MIN_PASSWORD:
            error = f"Password must be at least {MIN_PASSWORD} characters."
            reason = "short_password"
        elif password != request.form.get("password2", ""):
            error = "The passwords do not match."
            reason = "password_mismatch"
        else:
            try:
                with db() as conn:
                    user_id = conn.execute(
                        "INSERT INTO users (username, password_hash) VALUES (%s, %s) RETURNING id",
                        (username, generate_password_hash(password)),
                    ).fetchone()[0]
            except psycopg.errors.UniqueViolation:
                error = "That username is taken."
                reason = "username_taken"
            else:
                log_event("signup_success", username, user_id=user_id)
                start_session(user_id, username)
                return redirect(url_for("account"))
        log_event("signup_failure", username, reason=reason)
    return render_template_string(SIGNUP, error=error, username=username)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with db() as conn:
            row = conn.execute(
                "SELECT id, username, password_hash FROM users WHERE lower(username) = lower(%s)",
                (username,),
            ).fetchone()
        if row and check_password_hash(row[2], password):
            log_event("login_success", row[1], user_id=row[0])
            start_session(row[0], row[1])
            return redirect(url_for("account"))
        # The log says why; the visitor only ever sees the same message.
        log_event("login_failure", username, reason="bad_password" if row else "unknown_user")
        error = "Wrong username or password."
    return render_template_string(LOGIN, error=error)


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    user_id = session["user_id"]  # from the signed cookie, never from the form
    error = None
    if request.method == "POST":
        sport = request.form.get("sport", "").strip()
        colour = request.form.get("colour", "").strip()
        if len(sport) > MAX_FIELD or len(colour) > MAX_FIELD:
            error = f"Keep each answer to {MAX_FIELD} characters."
        else:
            with db() as conn:
                conn.execute(
                    """INSERT INTO preferences (user_id, favorite_sport, car_colour, updated_at)
                       VALUES (%s, %s, %s, now())
                       ON CONFLICT (user_id) DO UPDATE
                         SET favorite_sport = EXCLUDED.favorite_sport,
                             car_colour     = EXCLUDED.car_colour,
                             updated_at     = now()""",
                    (user_id, sport or None, colour or None),
                )
            # Redirect after a POST so a page refresh doesn't resubmit the form.
            return redirect(url_for("account", saved=1))

    with db() as conn:
        row = conn.execute(
            """SELECT favorite_sport, car_colour, to_char(updated_at, 'YYYY-MM-DD HH24:MI "UTC"')
               FROM preferences WHERE user_id = %s""",
            (user_id,),
        ).fetchone()
    prefs = {"sport": row[0], "colour": row[1], "updated": row[2]} if row else None
    return render_template_string(
        ACCOUNT,
        username=session["user"],
        prefs=prefs,
        saved=request.args.get("saved") == "1",
        error=error,
        max_field=MAX_FIELD,
    )


@app.get("/admin")
def admin():
    # Old address from the first version of the site.
    return redirect(url_for("account"))


@app.post("/logout")
def logout():
    if "user" in session:
        log_event("logout", session["user"], user_id=session.get("user_id"))
    session.clear()
    return redirect(url_for("landing"))


@app.get("/healthz")
def healthz():
    return "ok"


# Runs once when gunicorn loads the app (--preload), before the workers start.
init_db()
