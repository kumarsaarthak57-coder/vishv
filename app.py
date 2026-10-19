import os, sqlite3, time, json, re, requests
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, g, session
from dotenv import load_dotenv

BASE = os.path.dirname(os.path.abspath(__file__))
# Load keys from .env; if the file was saved under a different name
# (e.g. "_env" or "env"), fall back to that so the keys are still found.
for _name in (".env", "_env", "env", ".env.txt"):
    _p = os.path.join(BASE, _name)
    if os.path.exists(_p):
        load_dotenv(_p, override=True)
        print(f"Loaded settings from {_p}")
        break
else:
    print(f"WARNING: no .env file found in {BASE} - API keys will be missing")
TMDB_KEY = os.getenv("TMDB_API_KEY")
OMDB_KEY = os.getenv("OMDB_API_KEY")
DB = os.path.join(BASE, "vishv.db")
TMDB_HOSTS = ["api.themoviedb.org", "api.tmdb.org"]

from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__, static_folder=os.path.join(BASE, "static"))
import secrets
# If SECRET_KEY is missing from .env, use a random one (logins reset on restart)
# rather than a publicly known default that would let anyone forge a session.
app.secret_key = os.getenv("SECRET_KEY") or secrets.token_hex(32)

# Enable ProxyFix so Flask recognizes forwarded Host, Port, Proto from VS Code tunnels
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Cookie settings: over HTTPS (VS Code / GitHub tunnels) use Secure + SameSite=None;
# over plain HTTP (e.g. http://192.168.x.x:5050 on your network) browsers drop
# Secure cookies, so use Lax and not-Secure there. Decided per request.
from flask.sessions import SecureCookieSessionInterface

class _SessionInterface(SecureCookieSessionInterface):
    def get_cookie_secure(self, app):
        return request.is_secure
    def get_cookie_samesite(self, app):
        return "None" if request.is_secure else "Lax"

app.session_interface = _SessionInterface()
app.config["SESSION_COOKIE_HTTPONLY"] = True

@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp

# ---- Login throttle: 5 wrong tries per IP+username per 5 minutes ----
_fails = {}
FAIL_LIMIT, FAIL_WINDOW = 5, 300

def _throttle_key(u):
    return (request.remote_addr, u.lower())

def _is_locked(u):
    k = _throttle_key(u)
    now = time.time()
    _fails[k] = [t for t in _fails.get(k, []) if now - t < FAIL_WINDOW]
    return len(_fails[k]) >= FAIL_LIMIT

# ---- Server-side response cache (5 min TTL) ----
_cache = {}
CACHE_TTL = 300

# ---- DB ----
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()

def init_db():
    with sqlite3.connect(DB) as c:
        existing = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")]

        if "entries" in existing:
            cols = [r[1] for r in c.execute("PRAGMA table_info(entries)")]
            if "user" not in cols:
                # Migrate old entries → add user column, reassign to host1
                host1 = os.getenv("HOST1_USER", "host1")
                c.execute("ALTER TABLE entries RENAME TO entries_old")
                c.execute("""CREATE TABLE entries(
                    user TEXT NOT NULL,
                    media_type TEXT, tmdb_id INTEGER, title TEXT, poster TEXT,
                    watchlist INTEGER DEFAULT 0, watched INTEGER DEFAULT 0,
                    rating INTEGER, review TEXT DEFAULT '',
                    updated TEXT DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY(user, media_type, tmdb_id))""")
                c.execute("""INSERT INTO entries(user,media_type,tmdb_id,title,poster,
                    watchlist,watched,rating,review,updated)
                    SELECT ?,media_type,tmdb_id,title,poster,
                    watchlist,watched,rating,review,updated FROM entries_old""", (host1,))
                c.execute("DROP TABLE entries_old")
        else:
            c.execute("""CREATE TABLE IF NOT EXISTS entries(
                user TEXT NOT NULL,
                media_type TEXT, tmdb_id INTEGER, title TEXT, poster TEXT,
                watchlist INTEGER DEFAULT 0, watched INTEGER DEFAULT 0,
                rating INTEGER, review TEXT DEFAULT '',
                updated TEXT DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(user, media_type, tmdb_id))""")

        c.execute("""CREATE TABLE IF NOT EXISTS users(
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user')""")

        c.execute("""CREATE TABLE IF NOT EXISTS shared_settings(
            key TEXT PRIMARY KEY,
            val TEXT NOT NULL)""")
        c.execute("INSERT OR IGNORE INTO shared_settings(key, val) VALUES('blend_title', 'Our Blended List')")

        # Titles that were ticked as watched but still had the wishlist flag: keep only "watched"
        c.execute("UPDATE entries SET watchlist=0 WHERE watched=1 AND watchlist=1")

        # Category / nation / order layout for the Wishlist and Watched views (one JSON per user)
        c.execute("""CREATE TABLE IF NOT EXISTS list_layout(
            user TEXT PRIMARY KEY,
            data TEXT NOT NULL)""")

        c.execute("""CREATE TABLE IF NOT EXISTS custom_list_names(
            username TEXT PRIMARY KEY,
            display_title TEXT NOT NULL)""")

        for key in ("HOST1", "HOST2"):
            u = os.getenv(f"{key}_USER")
            p = os.getenv(f"{key}_PASS")
            if u and p:
                c.execute("INSERT OR IGNORE INTO users(username,password,role) VALUES(?,?,?)",
                          (u, p, "host"))

# ---- Auth helpers ----
def require_auth(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if "user" not in session:
            return jsonify(error="Not authenticated"), 401
        return f(*args, **kwargs)
    return wrap

def require_host(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if "user" not in session:
            return jsonify(error="Not authenticated"), 401
        if session.get("role") != "host":
            return jsonify(error="Hosts only"), 403
        return f(*args, **kwargs)
    return wrap

# ---- Routes ----
@app.get("/")
def index():
    # If there is an index.html in both static/ and next to app.py, serve the newest one
    # (so an old copy left in one place can never hide the updated one).
    found = [os.path.join(f, "index.html") for f in (app.static_folder, BASE)
             if os.path.exists(os.path.join(f, "index.html"))]
    if not found:
        return ("index.html not found.", 404)
    best = max(found, key=os.path.getmtime)
    resp = send_from_directory(os.path.dirname(best), "index.html")
    resp.headers["Cache-Control"] = "no-cache"   # always re-check, so updates show without a hard refresh
    return resp

@app.post("/api/login")
def login():
    d = request.get_json(force=True) or {}
    u, p = d.get("username", ""), d.get("password", "")
    if _is_locked(u):
        return jsonify(error="Too many wrong attempts. Try again in a few minutes."), 429
    with sqlite3.connect(DB) as c:
        c.row_factory = sqlite3.Row
        row = c.execute("SELECT * FROM users WHERE username=? AND password=?", (u, p)).fetchone()
    if not row:
        _fails.setdefault(_throttle_key(u), []).append(time.time())
        return jsonify(error="Invalid credentials"), 401
    _fails.pop(_throttle_key(u), None)
    session["user"] = row["username"]
    session["role"] = row["role"]
    return jsonify(username=row["username"], role=row["role"])

@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)

@app.get("/api/me")
def me():
    if "user" not in session:
        return jsonify(error="Not authenticated"), 401
    return jsonify(username=session["user"], role=session.get("role", "user"))

@app.post("/api/change-password")
@require_auth
def change_password():
    d = request.get_json(force=True) or {}
    new_pass = d.get("password", "").strip()
    if not new_pass:
        return jsonify(error="New password cannot be empty"), 400
    db().execute("UPDATE users SET password=? WHERE username=?", (new_pass, session["user"]))
    db().commit()
    return jsonify(ok=True)

@app.post("/api/change-username")
@require_auth
def change_username():
    d = request.get_json(force=True) or {}
    new_user = d.get("username", "").strip()
    old_user = session["user"]
    if not new_user or len(new_user) < 2:
        return jsonify(error="Username must be at least 2 characters"), 400
    if new_user == old_user:
        return jsonify(ok=True)
    existing = db().execute("SELECT 1 FROM users WHERE username=?", (new_user,)).fetchone()
    if existing:
        return jsonify(error="Username already taken"), 409
    
    # Update users table and all cascade entries
    role = session.get("role", "user")
    db().execute("UPDATE users SET username=? WHERE username=?", (new_user, old_user))
    db().execute("UPDATE entries SET user=? WHERE user=?", (new_user, old_user))
    db().execute("DELETE FROM list_layout WHERE user=?", (new_user,))
    db().execute("UPDATE list_layout SET user=? WHERE user=?", (new_user, old_user))
    db().commit()
    session["user"] = new_user
    return jsonify(username=new_user, role=role)

# ---- Blended List Name (changeable by user & friend) ----
@app.get("/api/blend-title")
@require_auth
def get_blend_title():
    row = db().execute("SELECT val FROM shared_settings WHERE key='blend_title'").fetchone()
    return jsonify(title=row["val"] if row else "Our Blended List")

@app.post("/api/blend-title")
@require_auth
def set_blend_title():
    d = request.get_json(force=True) or {}
    t = d.get("title", "").strip()
    if not t:
        return jsonify(error="Title cannot be empty"), 400
    db().execute("INSERT OR REPLACE INTO shared_settings(key, val) VALUES('blend_title', ?)", (t,))
    db().commit()
    return jsonify(title=t)

# ---- Custom List Titles (independent of username) ----
@app.get("/api/list-titles")
@require_auth
def get_list_titles():
    rows = db().execute("SELECT username, display_title FROM custom_list_names").fetchall()
    return jsonify({r["username"]: r["display_title"] for r in rows})

@app.post("/api/list-titles")
@require_auth
def set_list_title():
    d = request.get_json(force=True) or {}
    target_user = d.get("username", session["user"]).strip()
    title = d.get("title", "").strip()
    if not title:
        return jsonify(error="Title cannot be empty"), 400
    db().execute("INSERT OR REPLACE INTO custom_list_names(username, display_title) VALUES(?, ?)", (target_user, title))
    db().commit()
    return jsonify(username=target_user, title=title)

# ---- User management (hosts only) ----
@app.get("/api/users")
@require_host
def list_users():
    rows = db().execute("SELECT username, role, password FROM users ORDER BY role DESC, username").fetchall()
    return jsonify([dict(r) for r in rows])

@app.post("/api/users/<name>/password")
@require_host
def reset_user_password(name):
    d = request.get_json(force=True) or {}
    new_pass = d.get("password", "").strip()
    if not new_pass:
        return jsonify(error="New password cannot be empty"), 400
    if not db().execute("SELECT 1 FROM users WHERE username=?", (name,)).fetchone():
        return jsonify(error="User not found"), 404
    db().execute("UPDATE users SET password=? WHERE username=?", (new_pass, name))
    db().commit()
    return jsonify(ok=True, username=name, password=new_pass)

@app.post("/api/users")
@require_host
def create_user():
    d = request.get_json(force=True) or {}
    u, p = d.get("username", "").strip(), d.get("password", "").strip()
    if not u or not p:
        return jsonify(error="Username and password required"), 400
    if len(u) < 2:
        return jsonify(error="Username too short"), 400
    existing = db().execute("SELECT 1 FROM users WHERE username=?", (u,)).fetchone()
    if existing:
        return jsonify(error="Username already exists"), 409
    db().execute("INSERT INTO users(username,password,role) VALUES(?,?,?)", (u, p, "user"))
    db().commit()
    return jsonify(username=u, role="user"), 201

@app.delete("/api/users/<name>")
@require_host
def delete_user(name):
    row = db().execute("SELECT role FROM users WHERE username=?", (name,)).fetchone()
    if not row:
        return jsonify(error="User not found"), 404
    if row["role"] == "host":
        return jsonify(error="Cannot remove a host"), 403
    db().execute("DELETE FROM users WHERE username=?", (name,))
    db().execute("DELETE FROM entries WHERE user=?", (name,))
    db().execute("DELETE FROM list_layout WHERE user=?", (name,))
    db().execute("DELETE FROM custom_list_names WHERE username=?", (name,))
    db().commit()
    return jsonify(ok=True)

@app.get("/api/allusers")
@require_auth
def all_users():
    rows = db().execute("SELECT username FROM users ORDER BY username").fetchall()
    return jsonify([r["username"] for r in rows])

_session = requests.Session()
_good_host = None  # last TMDB host that answered

# ---- TMDB / OMDb proxies with caching ----
@app.get("/api/tmdb/<path:p>")
@require_auth
def tmdb(p):
    if not TMDB_KEY:
        return jsonify(error="TMDB_API_KEY is missing."), 500
    params = {**request.args, "api_key": TMDB_KEY}
    cache_key = f"tmdb:{p}:{sorted(params.items())}"
    now = time.time()
    if cache_key in _cache and now - _cache[cache_key][0] < CACHE_TTL:
        content, status = _cache[cache_key][1]
        return (content, status, {"Content-Type": "application/json"})
    last = None
    global _good_host
    for host in sorted(TMDB_HOSTS, key=lambda h: h != _good_host):
        try:
            r = _session.get(f"https://{host}/3/{p}", params=params, timeout=5)
            _good_host = host
            if r.ok:
                _cache[cache_key] = (now, (r.content, r.status_code))
            return (r.content, r.status_code, {"Content-Type": "application/json"})
        except requests.RequestException as e:
            last = e
            print(f"TMDB via {host} failed:", type(e).__name__)
    return jsonify(error="Could not reach TMDB: " + type(last).__name__), 502

@app.get("/api/omdb")
@require_auth
def omdb():
    params = {"i": request.args.get("i", ""), "plot": "full", "apikey": OMDB_KEY}
    cache_key = f"omdb:{sorted(params.items())}"
    now = time.time()
    if cache_key in _cache and now - _cache[cache_key][0] < CACHE_TTL:
        content, status = _cache[cache_key][1]
        return (content, status, {"Content-Type": "application/json"})
    try:
        r = requests.get("https://www.omdbapi.com/", params=params, timeout=15)
        if r.ok:
            _cache[cache_key] = (now, (r.content, r.status_code))
    except requests.RequestException as e:
        print("OMDb request failed:", repr(e))
        return jsonify(error="Could not reach OMDb"), 502
    return (r.content, r.status_code, {"Content-Type": "application/json"})

# ---- Per-user data ----
@app.get("/api/my")
@require_auth
def my_all():
    rows = db().execute("SELECT * FROM entries WHERE user=? ORDER BY updated DESC",
                        (session["user"],)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.get("/api/my/user/<name>")
@require_auth
def my_other(name):
    rows = db().execute("SELECT * FROM entries WHERE user=? ORDER BY updated DESC",
                        (name,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.get("/api/my/<t>/<int:i>")
@require_auth
def my_one(t, i):
    r = db().execute("SELECT * FROM entries WHERE user=? AND media_type=? AND tmdb_id=?",
                     (session["user"], t, i)).fetchone()
    return jsonify(dict(r) if r else {})

@app.post("/api/my/<t>/<int:i>")
@require_auth
def my_save(t, i):
    user = session["user"]
    d = request.get_json(force=True) or {}
    cur = db().execute("SELECT * FROM entries WHERE user=? AND media_type=? AND tmdb_id=?",
                       (user, t, i)).fetchone()
    row = dict(cur) if cur else dict(user=user, media_type=t, tmdb_id=i, title="", poster="",
                                     watchlist=0, watched=0, rating=None, review="")
    for k in ("title", "poster", "watchlist", "watched", "rating", "review"):
        if k in d:
            row[k] = d[k]
    # A title is either on the wishlist or watched, never both: choosing one clears the other.
    if d.get("watched") and not d.get("watchlist"):
        row["watchlist"] = 0
    elif d.get("watchlist") and not d.get("watched"):
        row["watched"] = 0
    db().execute("""INSERT OR REPLACE INTO entries
        (user,media_type,tmdb_id,title,poster,watchlist,watched,rating,review,updated)
        VALUES(?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)""",
        (user, t, i, row["title"], row["poster"], row["watchlist"], row["watched"],
         row["rating"], row["review"]))
    db().commit()
    return jsonify(row)

# ---- Wishlist / Watched layout: category (gl / bl / normal), nation and order ----
_LAYOUT_CATS = ("gl", "bl", "normal")
_KEY_RE = re.compile(r"^(movie|tv)_\d+$")
_NATION_RE = re.compile(r"^[A-Za-z]{2,8}$")

def _clean_layout(d):
    """Keep only well-formed data so a bad request can never store junk."""
    items, nations = {}, {}
    raw_items = d.get("items") if isinstance(d.get("items"), dict) else {}
    for k, v in list(raw_items.items())[:5000]:
        if not (isinstance(k, str) and _KEY_RE.match(k) and isinstance(v, dict)):
            continue
        c, n, p = v.get("c"), v.get("n"), v.get("p")
        if c not in _LAYOUT_CATS or not (isinstance(n, str) and _NATION_RE.match(n)):
            continue
        row = {"c": c, "n": n.upper()}
        if isinstance(p, int) and not isinstance(p, bool) and 0 <= p < 100000:
            row["p"] = p
        items[k] = row
    raw_nations = d.get("nations") if isinstance(d.get("nations"), dict) else {}
    for cat in _LAYOUT_CATS:
        lst = raw_nations.get(cat)
        if not isinstance(lst, list):
            continue
        out = []
        for n in lst[:300]:
            if isinstance(n, str) and _NATION_RE.match(n) and n.upper() not in out:
                out.append(n.upper())
        nations[cat] = out
    return {"items": items, "nations": nations}

@app.get("/api/layout/<name>")
@require_auth
def get_layout(name):
    row = db().execute("SELECT data FROM list_layout WHERE user=?", (name,)).fetchone()
    try:
        data = _clean_layout(json.loads(row["data"])) if row else {"items": {}, "nations": {}}
    except ValueError:
        data = {"items": {}, "nations": {}}
    return jsonify(data)

@app.post("/api/layout")
@require_auth
def save_layout():
    d = request.get_json(force=True, silent=True) or {}
    if not isinstance(d, dict):
        return jsonify(error="Bad layout"), 400
    clean = _clean_layout(d)
    db().execute("INSERT OR REPLACE INTO list_layout(user, data) VALUES(?, ?)",
                 (session["user"], json.dumps(clean)))
    db().commit()
    return jsonify(ok=True)

if __name__ == "__main__":
    init_db()
    port = int(os.getenv("PORT", 5050))
    cert, key = os.getenv("SSL_CERT"), os.getenv("SSL_KEY")
    ctx = None
    if cert and key:
        cert = cert if os.path.isabs(cert) else os.path.join(BASE, cert)
        key = key if os.path.isabs(key) else os.path.join(BASE, key)
        if os.path.exists(cert) and os.path.exists(key):
            ctx = (cert, key)
        else:
            print("SSL_CERT / SSL_KEY set in .env but the files were not found; starting without HTTPS.")
    scheme = "https" if ctx else "http"
    print(f"Open {scheme}://127.0.0.1:{port}/ in your browser")
    app.run(host="0.0.0.0", port=port, debug=os.getenv("FLASK_DEBUG") == "1", ssl_context=ctx)
