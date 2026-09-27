#!/usr/bin/env python3
"""Conticini - private boat area: boat documents + expense log.

Security: Argon2id, mandatory TOTP (Google Authenticator), HttpOnly/Secure/
SameSite=Strict cookies, CSRF token on every POST, rate limiting, files
served only with a valid session after magic-byte verification.
"""
import os
import io
import re
import sqlite3
import time
import uuid
import hmac
import secrets
import datetime
import ipaddress
import urllib.parse

from flask import (Flask, request, redirect, url_for, session, abort,
                   render_template, send_file, jsonify, flash)
from argon2 import PasswordHasher
import pyotp
import qrcode
import qrcode.image.svg

APP_VERSION = "1.4.0"
DATA_DIR = os.environ.get("CONTICINI_DATA", "/data")
DB_PATH = os.path.join(DATA_DIR, "conticini.db")
FILES_DIR = os.path.join(DATA_DIR, "files")
URL_PREFIX = os.environ.get("CONTICINI_PREFIX", "/conticini")
BOAT_NAME = os.environ.get("BOAT_NAME", "Nautilus")
# token for internal APIs (nautilus-telemetry writes/reads boat positions)
INTERNAL_TOKEN = os.environ.get("INTERNAL_TOKEN", "")
BOAT_MIN_MOVE_M = 25.0   # dedup: a fix closer than 25 m to the previous one is not saved

MAX_UPLOAD = 25 * 1024 * 1024          # 25 MB per file
MAX_DOCS = 20 * 1024 * 1024           # 20 MB per document PDF
LOGIN_MAX_FAILS = 5                    # attempts before lockout
LOGIN_LOCK_MINUTES = 15

DOC_CATEGORIES = ["Assicurazione", "Certificati di sicurezza", "Contratti",
                  "Licenza RTF", "Manuali", "Preventivi", "Tagliandi", "Altro"]
EXP_CATEGORIES = ["Carburante", "Ormeggio", "Manutenzione ordinaria",
                  "Manutenzione straordinaria", "Attrezzatura",
                  "Assicurazione", "Altro"]
CURRENCIES = ["EUR", "USD", "CHF", "GBP", "DKK", "SEK", "NOK"]

# --------------------------------------------------------------------------
# Security: persistent secret + in-memory rate limiter
# --------------------------------------------------------------------------
os.makedirs(FILES_DIR, exist_ok=True)
SECRET_FILE = os.path.join(DATA_DIR, "secret_key")
if not os.path.exists(SECRET_FILE):
    with open(SECRET_FILE, "wb") as f:
        f.write(secrets.token_bytes(32))
with open(SECRET_FILE, "rb") as f:
    SECRET_KEY = f.read()

_login_fails = {}   # key (ip, username) -> (fails, lock_until_ts)


def _client_ip():
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.remote_addr or "?"


def _login_blocked(ip, username):
    rec = _login_fails.get((ip, username))
    if not rec:
        return False
    fails, until = rec
    if until and until > time.time():
        return True
    if until and until <= time.time():
        _login_fails.pop((ip, username), None)
    return False


def _login_fail(ip, username):
    fails, _ = _login_fails.get((ip, username), (0, 0))
    fails += 1
    until = 0
    if fails >= LOGIN_MAX_FAILS:
        until = time.time() + LOGIN_LOCK_MINUTES * 60
        fails = 0
    _login_fails[(ip, username)] = (fails, until)


def _login_ok(ip, username):
    _login_fails.pop((ip, username), None)


# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    totp_secret TEXT,
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    is_admin INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    last_login TEXT
);
CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    stored_name TEXT UNIQUE NOT NULL,
    original_name TEXT NOT NULL,
    category TEXT NOT NULL,
    description TEXT DEFAULT '',
    size INTEGER NOT NULL,
    uploaded_by TEXT NOT NULL,
    uploaded_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS expenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date TEXT NOT NULL,
    amount REAL NOT NULL,
    currency TEXT NOT NULL DEFAULT 'EUR',
    category TEXT NOT NULL,
    description TEXT DEFAULT '',
    paid INTEGER NOT NULL DEFAULT 0,
    paid_date TEXT DEFAULT '',
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS attachments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    expense_id INTEGER NOT NULL REFERENCES expenses(id) ON DELETE CASCADE,
    stored_name TEXT UNIQUE NOT NULL,
    original_name TEXT NOT NULL,
    size INTEGER NOT NULL,
    mime TEXT NOT NULL,
    uploaded_by TEXT NOT NULL,
    uploaded_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS boat_positions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    latitude REAL NOT NULL,
    longitude REAL NOT NULL,
    speed_kn REAL,
    heading REAL,
    satellites INTEGER,
    altitude_m REAL,
    source TEXT NOT NULL DEFAULT 'live'
);
CREATE INDEX IF NOT EXISTS idx_exp_date ON expenses(date);
CREATE INDEX IF NOT EXISTS idx_att_exp ON attachments(expense_id);
"""


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    with db() as conn:
        conn.executescript(SCHEMA)
        # migrations for existing DBs
        bcols = [r["name"] for r in conn.execute("PRAGMA table_info(boat_positions)")]
        if "source" not in bcols:
            conn.execute("ALTER TABLE boat_positions ADD COLUMN source TEXT NOT NULL DEFAULT 'live'")
        cols = [r["name"] for r in conn.execute("PRAGMA table_info(expenses)")]
        if "paid" not in cols:
            conn.execute("ALTER TABLE expenses ADD COLUMN paid INTEGER NOT NULL DEFAULT 0")
        if "paid_date" not in cols:
            conn.execute("ALTER TABLE expenses ADD COLUMN paid_date TEXT DEFAULT ''")
        admin_user = os.environ.get("ADMIN_USERNAME", "federico")
        admin_pass = os.environ.get("ADMIN_PASSWORD", "")
        if not admin_pass:
            raise SystemExit("ADMIN_PASSWORD obbligatoria: impostala in .env")
        row = conn.execute("SELECT id FROM users WHERE username=?",
                           (admin_user,)).fetchone()
        if not row:
            conn.execute(
                "INSERT INTO users (username, password_hash, is_admin, created_at)"
                " VALUES (?,?,1,?)",
                (admin_user, _ph.hash(admin_pass),
                 datetime.datetime.now().isoformat(timespec="seconds")))
            print(f"[init] utente admin creato: {admin_user}")


# --------------------------------------------------------------------------
# Flask + URL prefix (behind reverse proxy)
# --------------------------------------------------------------------------
class PrefixMiddleware:
    """Makes the app work both directly (:8080) and behind a URL prefix."""
    def __init__(self, wsgi, prefix):
        self.wsgi = wsgi
        self.prefix = prefix

    def __call__(self, environ, start_response):
        pi = environ.get("PATH_INFO", "")
        if pi.startswith(self.prefix):
            environ["SCRIPT_NAME"] = self.prefix
            environ["PATH_INFO"] = pi[len(self.prefix):] or "/"
        return self.wsgi(environ, start_response)


app = Flask(__name__)
app.wsgi_app = PrefixMiddleware(app.wsgi_app, URL_PREFIX)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_NAME="conticini_sess",
    SESSION_COOKIE_HTTPONLY=True,
    # served over HTTPS; SECURE_COOKIES=0 only for local http testing
    SESSION_COOKIE_SECURE=os.environ.get("SECURE_COOKIES", "1") != "0",
    SESSION_COOKIE_SAMESITE="Strict",
    PERMANENT_SESSION_LIFETIME=datetime.timedelta(hours=12),
    SESSION_REFRESH_EACH_REQUEST=True,
    MAX_CONTENT_LENGTH=MAX_UPLOAD,
    APPLICATION_ROOT=URL_PREFIX,
    JSON_SORT_KEYS=False,
)
_ph = PasswordHasher()

# valid users for safe upload: magic-byte verification
def _sniff_mime(head: bytes, allowed):
    """allowed: list of tuples (magic_prefix, mime, ext)."""
    for magic, mime, ext in allowed:
        if head.startswith(magic):
            return mime, ext
    return None, None


PDF_MAGES = [(b"%PDF-", "application/pdf", "pdf")]
IMG_MAGES = [(b"\xff\xd8\xff", "image/jpeg", "jpg"),
             (b"\x89PNG\r\n\x1a\n", "image/png", "png")]


def _safe_filename(name):
    name = os.path.basename(name or "file")
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    return name[:80] or "file"


def _store_file(fs, allowed):
    """Save a FileStorage after magic-byte verification. Returns (stored, size, mime, ext)."""
    head = fs.stream.read(16)
    fs.stream.seek(0)
    mime, ext = _sniff_mime(head, allowed)
    if not mime:
        return None
    stored = uuid.uuid4().hex + "." + ext
    path = os.path.join(FILES_DIR, stored)
    size = 0
    with open(path, "wb") as out:
        while True:
            chunk = fs.stream.read(1024 * 256)
            if not chunk:
                break
            size += len(chunk)
            out.write(chunk)
    if size == 0:
        os.unlink(path)
        return None
    return stored, size, mime


# --------------------------------------------------------------------------
# Security: CSRF + headers
# --------------------------------------------------------------------------
@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; frame-src 'self'; "
        "object-src 'none'; base-uri 'self'")
    return resp


def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


def check_csrf():
    sent = request.form.get("_csrf", "")
    if not hmac.compare_digest(sent, session.get("_csrf", "")):
        abort(403)


@app.before_request
def csrf_protect():
    if request.method == "POST" and not request.path.startswith("/internal"):
        # login uses a fresh session: token still required
        check_csrf()


def login_required(view):
    from functools import wraps
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    from functools import wraps
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user") or not session.get("is_admin"):
            abort(403)
        return view(*args, **kwargs)
    return wrapped


@app.context_processor
def template_globals():
    return {"version": APP_VERSION, "csrf": csrf_token(), "boat_name": BOAT_NAME}


# --------------------------------------------------------------------------
# Authentication (Argon2id password + mandatory TOTP)
# --------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method in ("GET", "HEAD"):
        session.clear()
        session["_csrf"] = secrets.token_hex(16)
        return render_template("login.html", csrf=csrf_token(), error=None)

    username = (request.form.get("username") or "").strip().lower()
    password = request.form.get("password") or ""
    totp_code = (request.form.get("totp") or "").strip()
    ip = _client_ip()

    if _login_blocked(ip, username):
        return render_template("login.html", csrf=csrf_token(),
            error="Troppi tentativi: attendi 15 minuti."), 429

    # step 2: password already verified in this session, only the code is missing
    pre_authed = (session.get("pre_auth") == username and not password
                  and bool(totp_code))

    with db() as conn:
        u = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

    if not u:
        # timing: dummy verify to avoid revealing that the user exists
        try:
            _ph.verify(_argon2_dummy, password)
        except Exception:
            pass
        _login_fail(ip, username)
        return render_template("login.html", csrf=csrf_token(),
                               error="Credenziali non valide."), 401

    if not pre_authed:
        try:
            _ph.verify(u["password_hash"], password)
        except Exception:
            _login_fail(ip, username)
            return render_template("login.html", csrf=csrf_token(),
                                   error="Credenziali non valide."), 401

    # --- password OK: handle 2FA ---
    if not u["totp_enabled"]:
        # first setup: show QR (once per session)
        if session.get("pre_totp_user") != u["username"]:
            session["pre_totp_user"] = u["username"]
            session["pending_secret"] = pyotp.random_base32()
        return redirect(url_for("setup_totp"))

    session["pre_auth"] = u["username"]
    if not totp_code:
        return render_template("login.html", csrf=csrf_token(), totp_needed=True,
                               username=username, error=None)

    totp = pyotp.TOTP(u["totp_secret"])
    if not (totp.verify(totp_code, valid_window=1)):
        _login_fail(ip, username)
        return render_template("login.html", csrf=csrf_token(), totp_needed=True,
                               username=username,
                               error="Codice 2FA non valido."), 401

    _login_ok(ip, username)
    session.clear()
    session["_csrf"] = secrets.token_hex(16)
    session["user"] = u["username"]
    session["uid"] = u["id"]
    session["is_admin"] = bool(u["is_admin"])
    session.permanent = True
    with db() as conn:
        conn.execute("UPDATE users SET last_login=? WHERE id=?",
                     (datetime.datetime.now().isoformat(timespec="seconds"),
                      u["id"]))
    nxt = request.args.get("next") or ""
    if not re.match(r"^/[A-Za-z0-9/_-]*$", nxt) or nxt.startswith("//"):
        nxt = "/"
    return redirect(URL_PREFIX + nxt)


# dummy hash to equalize response timing on failed logins
try:
    _argon2_dummy = _ph.hash("dummy-password-timing-equalizer")
except Exception:
    _argon2_dummy = None


@app.route("/setup-totp")
def setup_totp():
    username = session.get("pre_totp_user")
    if not username:
        return redirect(url_for("login"))
    secret = session.get("pending_secret")
    if not secret:
        return redirect(url_for("login"))
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=username, issuer_name=f"{BOAT_NAME} Conticini")
    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
    buf = io.BytesIO()
    img.save(buf)
    qr_svg = buf.getvalue().decode()
    return render_template("setup_totp.html", csrf=csrf_token(), secret=secret,
                           qr_svg=qr_svg, username=username)


@app.route("/setup-totp", methods=["POST"])
def setup_totp_confirm():
    code = (request.form.get("totp") or "").strip()
    secret = session.get("pending_secret")
    username = session.get("pre_totp_user")
    if not secret or not username:
        return redirect(url_for("login"))
    if not pyotp.TOTP(secret).verify(code, valid_window=1):
        return render_template("setup_totp.html", csrf=csrf_token(),
                               secret=secret, username=username,
                               qr_svg=None, error="Codice non valido, riprova.")
    with db() as conn:
        conn.execute("UPDATE users SET totp_secret=?, totp_enabled=1 WHERE username=?",
                     (secret, username))
    session.pop("pending_secret", None)
    session.pop("pre_totp_user", None)
    # back to login: password + code just validated
    return redirect(url_for("login"))


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# --------------------------------------------------------------------------
# Internal APIs for nautilus-telemetry (boat positions), X-Internal-Token
# --------------------------------------------------------------------------
def _internal_ok():
    tok = request.headers.get("X-Internal-Token", "")
    return bool(INTERNAL_TOKEN) and hmac.compare_digest(tok, INTERNAL_TOKEN)


def _haversine_m(lat1, lon1, lat2, lon2):
    from math import radians, sin, cos, asin, sqrt
    rlat1, rlon1, rlat2, rlon2 = map(radians, (lat1, lon1, lat2, lon2))
    a = (sin((rlat2 - rlat1) / 2) ** 2 +
         cos(rlat1) * cos(rlat2) * sin((rlon2 - rlon1) / 2) ** 2)
    return 2 * 6371000 * asin(sqrt(a))


@app.route("/internal/boat/position", methods=["POST"])
def internal_save_position():
    """nautilus-telemetry posts valid GPS fixes here (dedup < 25 m)."""
    if not _internal_ok():
        abort(403)
    d = request.get_json(silent=True) or {}
    try:
        lat = float(d["latitude"]); lon = float(d["longitude"])
        if not (-90 <= lat <= 90 and -180 <= lon <= 180):
            raise ValueError
    except (KeyError, TypeError, ValueError):
        return jsonify({"error": "lat/long non valide"}), 400
    ts = d.get("timestamp") or datetime.datetime.now().isoformat(timespec="seconds")
    with db() as conn:
        last = conn.execute("SELECT latitude, longitude FROM boat_positions"
                             " ORDER BY id DESC LIMIT 1").fetchone()
        if last and _haversine_m(last["latitude"], last["longitude"], lat, lon) < BOAT_MIN_MOVE_M:
            return jsonify({"saved": False, "reason": "ferma (<25 m dal precedente)"})
        conn.execute(
            "INSERT INTO boat_positions (ts, latitude, longitude, speed_kn,"
            " heading, satellites, altitude_m, source) VALUES (?,?,?,?,?,?,?,?)",
            (ts, lat, lon, d.get("speed"), d.get("heading"),
             d.get("satellites"), d.get("altitude_m"),
             ("buffer" if d.get("source") == "buffer" else "live")))
    return jsonify({"saved": True})


@app.route("/internal/boat/track-history")
def internal_track_history():
    """Boat position history for nautilus-telemetry (same filters as the public API)."""
    if not _internal_ok():
        abort(403)
    last = request.args.get("last")
    start = request.args.get("start_date", "")
    end = request.args.get("end_date", "")
    with db() as conn:
        if last is not None:
            try:
                n = max(1, min(int(last), 5000))
            except ValueError:
                n = 500
            rows = conn.execute("SELECT * FROM (SELECT * FROM boat_positions"
                                " ORDER BY id DESC LIMIT ?) ORDER BY id", (n,)).fetchall()
        else:
            if start and not re.match(r"^\d{4}-\d{2}-\d{2}$", start):
                return jsonify({"error": "start_date non valida"}), 400
            if end and not re.match(r"^\d{4}-\d{2}-\d{2}$", end):
                return jsonify({"error": "end_date non valida"}), 400
            if not start:
                start = (datetime.datetime.now() - datetime.timedelta(days=730)).strftime("%Y-%m-%d")
            if not end:
                end = datetime.datetime.now().strftime("%Y-%m-%d")
            rows = conn.execute("SELECT * FROM boat_positions WHERE ts >= ?"
                                " AND ts < date(?, '+1 day') ORDER BY id",
                                (start, end)).fetchall()
    points = [{"timestamp": r["ts"], "latitude": round(r["latitude"], 6),
              "longitude": round(r["longitude"], 6),
              "speed": r["speed_kn"], "heading": r["heading"],
              "source": r["source"] if "source" in r.keys() else "live"} for r in rows]
    return jsonify({"count": len(points), "points": points})


# --------------------------------------------------------------------------
# Home
# --------------------------------------------------------------------------
@app.route("/")
@login_required
def index():
    with db() as conn:
        n_docs = conn.execute("SELECT COUNT(*) c FROM documents").fetchone()["c"]
        n_exp = conn.execute("SELECT COUNT(*) c FROM expenses").fetchone()["c"]
        tot = conn.execute(
            "SELECT currency, SUM(amount) s, COUNT(*) n FROM expenses"
            " GROUP BY currency ORDER BY s DESC").fetchall()
        recent = conn.execute(
            "SELECT * FROM expenses ORDER BY date DESC, id DESC LIMIT 5").fetchall()
        yearly_rows = conn.execute(
            "SELECT substr(date,1,4) year, created_by, currency, paid,"
            " SUM(amount) s, COUNT(*) n FROM expenses"
            " GROUP BY year, created_by, currency, paid"
            " ORDER BY year DESC, currency, s DESC").fetchall()
    # organize: year -> currency -> {user: {paid: sum, unpaid: sum,
    # n: items}, total: ..., total_unpaid: ...}
    years = {}
    for r in yearly_rows:
        y = years.setdefault(r["year"], {})
        c = y.setdefault(r["currency"],
                         {"users": {}, "total": 0.0, "total_unpaid": 0.0,
                          "count": 0})
        u = c["users"].setdefault(r["created_by"],
                                  {"paid": 0.0, "unpaid": 0.0, "n": 0})
        if r["paid"]:
            u["paid"] += r["s"]
        else:
            u["unpaid"] += r["s"]
            c["total_unpaid"] += r["s"]
        u["n"] += r["n"]
        c["total"] += r["s"]
        c["count"] += r["n"]
    return render_template("index.html", version=APP_VERSION, n_docs=n_docs,
                           n_exp=n_exp, totals=tot, recent=recent, years=years,
                           csrf=csrf_token())


# --------------------------------------------------------------------------
# Boat documents (PDF only)
# --------------------------------------------------------------------------
@app.route("/documenti")
@login_required
def documents():
    q = (request.args.get("q") or "").strip()
    cat = (request.args.get("cat") or "").strip()
    sql = "SELECT * FROM documents WHERE 1=1"
    args = []
    if q:
        sql += " AND (original_name LIKE ? OR description LIKE ?)"
        args += [f"%{q}%"] * 2
    if cat and cat in DOC_CATEGORIES:
        sql += " AND category=?"
        args.append(cat)
    sql += " ORDER BY uploaded_at DESC"
    with db() as conn:
        rows = conn.execute(sql, args).fetchall()
    return render_template("documents.html", docs=rows, csrf=csrf_token(),
                           categories=DOC_CATEGORIES, q=q, cat=cat,
                           max_mb=MAX_DOCS // (1024 * 1024))


@app.route("/documenti/upload", methods=["POST"])
@login_required
def documents_upload():
    fs = request.files.get("file")
    if not fs or not fs.filename:
        flash("Nessun file selezionato.")
        return redirect(url_for("documents"))
    if fs.content_length and fs.content_length > MAX_DOCS:
        flash("File troppo grande (max %d MB)." % (MAX_DOCS // 1024 // 1024))
        return redirect(url_for("documents"))
    stored = _store_file(fs, PDF_MAGES)
    if not stored:
        flash("Il file non è un PDF valido (verifica contenuto, non solo estensione).")
        return redirect(url_for("documents"))
    sname, size, _mime = stored
    cat = request.form.get("category")
    if cat not in DOC_CATEGORIES:
        cat = "Altro"
    with db() as conn:
        conn.execute(
            "INSERT INTO documents (stored_name, original_name, category,"
            " description, size, uploaded_by, uploaded_at)"
            " VALUES (?,?,?,?,?,?,?)",
            (sname, _safe_filename(fs.filename), cat,
             (request.form.get("description") or "")[:200], size,
             session["user"],
             datetime.datetime.now().isoformat(timespec="seconds")))
    flash("Documento caricato.")
    return redirect(url_for("documents"))


@app.route("/documenti/<int:doc_id>/view")
@login_required
def document_view(doc_id):
    with db() as conn:
        d = conn.execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
    if not d:
        abort(404)
    return send_file(os.path.join(FILES_DIR, d["stored_name"]),
                     mimetype="application/pdf", as_attachment=False,
                     download_name=d["original_name"])


@app.route("/documenti/<int:doc_id>/download")
@login_required
def document_download(doc_id):
    with db() as conn:
        d = conn.execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
    if not d:
        abort(404)
    return send_file(os.path.join(FILES_DIR, d["stored_name"]),
                     mimetype="application/pdf", as_attachment=True,
                     download_name=d["original_name"])


@app.route("/documenti/<int:doc_id>/modifica")
@login_required
def document_edit(doc_id):
    with db() as conn:
        d = conn.execute("SELECT * FROM documents WHERE id=?",
                         (doc_id,)).fetchone()
    if not d:
        abort(404)
    return render_template("document_edit.html", d=d,
                           csrf=csrf_token(), categories=DOC_CATEGORIES)


@app.route("/documenti/<int:doc_id>/modifica", methods=["POST"])
@login_required
def document_update(doc_id):
    with db() as conn:
        d = conn.execute("SELECT * FROM documents WHERE id=?",
                         (doc_id,)).fetchone()
        if not d:
            abort(404)
        cat = request.form.get("category")
        if cat not in DOC_CATEGORIES:
            cat = "Altro"
        conn.execute(
            "UPDATE documents SET category=?, description=?, original_name=?"
            " WHERE id=?",
            (cat, (request.form.get("description") or "")[:200],
             _safe_filename(request.form.get("original_name")
                            or d["original_name"]),
             doc_id))
    flash("Documento aggiornato.")
    return redirect(url_for("documents"))


@app.route("/documenti/<int:doc_id>/delete", methods=["POST"])
@login_required
def document_delete(doc_id):
    with db() as conn:
        d = conn.execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
        if d:
            conn.execute("DELETE FROM documents WHERE id=?", (doc_id,))
    if d:
        try:
            os.unlink(os.path.join(FILES_DIR, d["stored_name"]))
        except FileNotFoundError:
            pass
    return redirect(url_for("documents"))


# --------------------------------------------------------------------------
# Expense log
# --------------------------------------------------------------------------
@app.route("/spese")
@login_required
def expenses():
    dfrom = request.args.get("from") or ""
    dto = request.args.get("to") or ""
    cat = request.args.get("cat") or ""
    paid = request.args.get("paid") or ""
    sql = "SELECT * FROM expenses WHERE 1=1"
    args = []
    if dfrom and re.match(r"^\d{4}-\d{2}-\d{2}$", dfrom):
        sql += " AND date>=?"
        args.append(dfrom)
    if dto and re.match(r"^\d{4}-\d{2}-\d{2}$", dto):
        sql += " AND date<=?"
        args.append(dto)
    if cat and cat in EXP_CATEGORIES:
        sql += " AND category=?"
        args.append(cat)
    if paid == "1":
        sql += " AND paid=1"
    elif paid == "0":
        sql += " AND paid=0"
    sql += " ORDER BY date DESC, id DESC"
    with db() as conn:
        rows = conn.execute(sql, args).fetchall()
        att = {r["id"]: [] for r in rows}
        if rows:
            marks = ",".join("?" * len(rows))
            for a in conn.execute(
                    f"SELECT * FROM attachments WHERE expense_id IN ({marks})"
                    " ORDER BY id", [r["id"] for r in rows]):
                att[a["expense_id"]].append(a)
    totals = {}
    for r in rows:
        totals.setdefault(r["currency"], [0.0, 0])
        totals[r["currency"]][0] += r["amount"]
        totals[r["currency"]][1] += 1
    by_cat = {}
    for r in rows:
        key = (r["currency"], r["category"])
        by_cat.setdefault(key, 0.0)
        by_cat[key] += r["amount"]
    return render_template("expenses.html", rows=rows, atts=att,
                           csrf=csrf_token(), categories=EXP_CATEGORIES,
                           currencies=CURRENCIES, dfrom=dfrom, dto=dto,
                           cat=cat, paid=paid, totals=totals, by_cat=by_cat)


def _expense_form_fields():
    """Validate fields shared by new expense and edit. Returns (dict, error)."""
    date = request.form.get("date") or ""
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", date):
        return None, "Data non valida."
    try:
        amount = round(float(request.form.get("amount", "0").replace(",", ".")), 2)
        if amount <= 0 or amount > 10_000_000:
            raise ValueError
    except ValueError:
        return None, "Importo non valido."
    currency = request.form.get("currency")
    if currency not in CURRENCIES:
        currency = "EUR"
    cat = request.form.get("category")
    if cat not in EXP_CATEGORIES:
        cat = "Altro"
    paid = 1 if request.form.get("paid") == "on" else 0
    paid_date = request.form.get("paid_date") or ""
    if not paid:
        paid_date = ""
    elif paid_date and not re.match(r"^\d{4}-\d{2}-\d{2}$", paid_date):
        paid_date = date   # fallback: the expense date
    if not paid_date:
        paid_date = date if paid else ""
    return {"date": date, "amount": amount, "currency": currency,
            "category": cat, "description":
                (request.form.get("description") or "")[:500],
            "paid": paid, "paid_date": paid_date}, None


@app.route("/spese/nuova", methods=["POST"])
@login_required
def expense_new():
    f, err = _expense_form_fields()
    if err:
        flash(err)
        return redirect(url_for("expenses"))
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO expenses (date, amount, currency, category, description,"
            " paid, paid_date, created_by, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (f["date"], f["amount"], f["currency"], f["category"],
             f["description"], f["paid"], f["paid_date"],
             session["user"],
             datetime.datetime.now().isoformat(timespec="seconds")))
        exp_id = cur.lastrowid
        # attachments (PDF/JPG/PNG, magic bytes)
        for fs in request.files.getlist("files"):
            if not fs or not fs.filename:
                continue
            stored = _store_file(fs, PDF_MAGES + IMG_MAGES)
            if not stored:
                flash("Allegato ignorato (formato non valido): " + _safe_filename(fs.filename))
                continue
            sname, size, mime = stored
            conn.execute(
                "INSERT INTO attachments (expense_id, stored_name, original_name,"
                " size, mime, uploaded_by, uploaded_at) VALUES (?,?,?,?,?,?,?)",
                (exp_id, sname, _safe_filename(fs.filename), size, mime,
                 session["user"],
                 datetime.datetime.now().isoformat(timespec="seconds")))
    flash("Spesa registrata.")
    return redirect(url_for("expenses"))


@app.route("/spese/<int:exp_id>/modifica")
@login_required
def expense_edit(exp_id):
    with db() as conn:
        e = conn.execute("SELECT * FROM expenses WHERE id=?",
                         (exp_id,)).fetchone()
        if not e:
            abort(404)
        atts = conn.execute(
            "SELECT * FROM attachments WHERE expense_id=? ORDER BY id",
            (exp_id,)).fetchall()
    return render_template("expense_edit.html", e=e, atts=atts,
                           csrf=csrf_token(), categories=EXP_CATEGORIES,
                           currencies=CURRENCIES)


@app.route("/spese/<int:exp_id>/modifica", methods=["POST"])
@login_required
def expense_update(exp_id):
    f, err = _expense_form_fields()
    if err:
        flash(err)
        return redirect(url_for("expense_edit", exp_id=exp_id))
    with db() as conn:
        e = conn.execute("SELECT id FROM expenses WHERE id=?",
                         (exp_id,)).fetchone()
        if not e:
            abort(404)
        conn.execute(
            "UPDATE expenses SET date=?, amount=?, currency=?, category=?,"
            " description=?, paid=?, paid_date=? WHERE id=?",
            (f["date"], f["amount"], f["currency"], f["category"],
             f["description"], f["paid"], f["paid_date"], exp_id))
        # any new attachments (PDF/JPG/PNG, magic bytes)
        for fs in request.files.getlist("files"):
            if not fs or not fs.filename:
                continue
            stored = _store_file(fs, PDF_MAGES + IMG_MAGES)
            if not stored:
                flash("Allegato ignorato (formato non valido): "
                      + _safe_filename(fs.filename))
                continue
            sname, size, mime = stored
            conn.execute(
                "INSERT INTO attachments (expense_id, stored_name, original_name,"
                " size, mime, uploaded_by, uploaded_at) VALUES (?,?,?,?,?,?,?)",
                (exp_id, sname, _safe_filename(fs.filename), size, mime,
                 session["user"],
                 datetime.datetime.now().isoformat(timespec="seconds")))
    flash("Spesa aggiornata.")
    return redirect(url_for("expenses"))


@app.route("/spese/allegato/<int:att_id>/delete", methods=["POST"])
@login_required
def attachment_delete(att_id):
    with db() as conn:
        a = conn.execute("SELECT * FROM attachments WHERE id=?",
                         (att_id,)).fetchone()
        if not a:
            abort(404)
        conn.execute("DELETE FROM attachments WHERE id=?", (att_id,))
    try:
        os.unlink(os.path.join(FILES_DIR, a["stored_name"]))
    except FileNotFoundError:
        pass
    return redirect(url_for("expense_edit", exp_id=a["expense_id"]))


@app.route("/spese/<int:exp_id>/toggle-paid", methods=["POST"])
@login_required
def expense_toggle_paid(exp_id):
    paid_date = request.form.get("paid_date") or ""
    with db() as conn:
        e = conn.execute("SELECT paid, date FROM expenses WHERE id=?",
                         (exp_id,)).fetchone()
        if not e:
            abort(404)
        new_paid = 0 if e["paid"] else 1
        if new_paid:
            pd = paid_date if re.match(r"^\d{4}-\d{2}-\d{2}$", paid_date) else e["date"]
        else:
            pd = ""
        conn.execute("UPDATE expenses SET paid=?, paid_date=? WHERE id=?",
                     (new_paid, pd, exp_id))
    # safe redirect: same-host referrer only (no open redirect)
    ref = request.referrer or ""
    host = request.host_url
    nxt = ref if ref.startswith(host) else None
    return redirect(nxt or url_for("expenses"))


@app.route("/spese/<int:exp_id>/delete", methods=["POST"])
@login_required
def expense_delete(exp_id):
    with db() as conn:
        atts = conn.execute("SELECT stored_name FROM attachments WHERE expense_id=?",
                            (exp_id,)).fetchall()
        conn.execute("DELETE FROM expenses WHERE id=?", (exp_id,))
    for a in atts:
        try:
            os.unlink(os.path.join(FILES_DIR, a["stored_name"]))
        except FileNotFoundError:
            pass
    return redirect(url_for("expenses"))


@app.route("/spese/<int:att_id>/allegato")
@login_required
def attachment_download(att_id):
    with db() as conn:
        a = conn.execute("SELECT * FROM attachments WHERE id=?", (att_id,)).fetchone()
    if not a:
        abort(404)
    mime = a["mime"]
    return send_file(os.path.join(FILES_DIR, a["stored_name"]), mimetype=mime,
                    as_attachment=False, download_name=a["original_name"])


# --------------------------------------------------------------------------
# User management (admin only)
# --------------------------------------------------------------------------
@app.route("/utenti")
@admin_required
def users():
    with db() as conn:
        rows = conn.execute(
            "SELECT id, username, is_admin, totp_enabled, created_at, last_login"
            " FROM users ORDER BY id").fetchall()
    return render_template("users.html", users=rows, csrf=csrf_token())


@app.route("/utenti/nuovo", methods=["POST"])
@admin_required
def user_new():
    username = (request.form.get("username") or "").strip().lower()
    password = request.form.get("password") or ""
    if not re.match(r"^[a-z0-9._-]{3,30}$", username):
        flash("Username non valido (3-30 caratteri: lettere, numeri, . _ -).")
        return redirect(url_for("users"))
    if len(password) < 10:
        flash("Password troppo corta: minimo 10 caratteri.")
        return redirect(url_for("users"))
    with db() as conn:
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash, is_admin, created_at)"
                " VALUES (?,?,?,?)",
                (username, _ph.hash(password),
                 1 if request.form.get("is_admin") == "on" else 0,
                 datetime.datetime.now().isoformat(timespec="seconds")))
        except sqlite3.IntegrityError:
            flash("Utente già esistente.")
            return redirect(url_for("users"))
    flash("Utente creato: al primo accesso configurerà Google Authenticator.")
    return redirect(url_for("users"))


@app.route("/utenti/<int:user_id>/delete", methods=["POST"])
@admin_required
def user_delete(user_id):
    if user_id == session.get("uid"):
        flash("Non puoi eliminare te stesso.")
        return redirect(url_for("users"))
    with db() as conn:
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))
    return redirect(url_for("users"))


@app.route("/utenti/<int:user_id>/reset-totp", methods=["POST"])
@admin_required
def user_reset_totp(user_id):
    with db() as conn:
        conn.execute("UPDATE users SET totp_secret=NULL, totp_enabled=0 WHERE id=?",
                     (user_id,))
    flash("2FA azzerato: l'utente lo riconfigurerà al prossimo accesso.")
    return redirect(url_for("users"))


# --------------------------------------------------------------------------
# Personal password change
# --------------------------------------------------------------------------
@app.route("/profilo", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        old = request.form.get("old") or ""
        new1 = request.form.get("new1") or ""
        new2 = request.form.get("new2") or ""
        with db() as conn:
            u = conn.execute("SELECT * FROM users WHERE id=?",
                             (session["uid"],)).fetchone()
        try:
            _ph.verify(u["password_hash"], old)
        except Exception:
            flash("Password attuale errata.")
            return redirect(url_for("profile"))
        if new1 != new2 or len(new1) < 10:
            flash("Nuova password non valida o non coincidente (min 10 caratteri).")
            return redirect(url_for("profile"))
        with db() as conn:
            conn.execute("UPDATE users SET password_hash=? WHERE id=?",
                         (_ph.hash(new1), session["uid"]))
        flash("Password aggiornata.")
        return redirect(url_for("profile"))
    return render_template("profile.html", csrf=csrf_token(),
                           username=session["user"])


# --------------------------------------------------------------------------
# Healthcheck (for the reverse proxy)
# --------------------------------------------------------------------------
@app.route("/healthz")
def healthz():
    return jsonify(ok=True, version=APP_VERSION)


if __name__ == "__main__":
    init_db()
    print(f"[conticini] v{APP_VERSION} in ascolto su :8080 "
          f"(prefisso {URL_PREFIX}, dati in {DATA_DIR})")
    app.run(host="0.0.0.0", port=8080)
