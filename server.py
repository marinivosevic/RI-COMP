"""
RI-COMP CTF Challenge Server
A self-contained CTF web app with 6 levels and per-user flag randomization.
Run: pip install flask psycopg2-binary && python server.py
Requires: PostgreSQL on localhost:5433 (docker container ri-comp-postgres)
"""

import hashlib
import random
import string
import base64
import json as _json
import time
import re
import os
import hmac as _hmac
from functools import wraps
from contextlib import contextmanager

import psycopg2
import psycopg2.extras
from flask import (
    Flask, session, redirect, url_for, request,
    render_template, jsonify, make_response
)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'ri-comp-ctf-2026-s3cr3t-key')

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def _clean_dsn(url: str | None) -> str | None:
    """Strip query params that psycopg2 doesn't understand (e.g. Supabase's 'supa' param)."""
    if not url:
        return None
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    parsed = urlparse(url)
    # Keep only params psycopg2 recognises
    PG_PARAMS = {
        'sslmode', 'sslcert', 'sslkey', 'sslrootcert', 'sslcrl',
        'connect_timeout', 'client_encoding', 'options', 'application_name',
        'keepalives', 'keepalives_idle', 'keepalives_interval', 'keepalives_count',
        'target_session_attrs',
    }
    qs = parse_qs(parsed.query)
    clean_qs = {k: v for k, v in qs.items() if k in PG_PARAMS}
    cleaned = parsed._replace(query=urlencode(clean_qs, doseq=True))
    return urlunparse(cleaned)

DATABASE_URL = _clean_dsn(os.environ.get('DATABASE_URL') or os.environ.get('POSTGRES_URL'))

# Local fallback config (docker-compose setup)
DB_CONFIG = {
    'host': 'localhost',
    'port': 5433,
    'dbname': 'ctf',
    'user': 'ctf',
    'password': 'ctf2026',
}


@contextmanager
def get_db():
    """Yield a (connection, cursor) pair, auto-commit on success."""
    if DATABASE_URL:
        conn = psycopg2.connect(DATABASE_URL)
    else:
        conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        yield conn, cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()


def init_db():
    """Create tables if they don't exist."""
    with get_db() as (conn, cur):
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(20) UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT NOW()
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS solves (
                id SERIAL PRIMARY KEY,
                username VARCHAR(20) NOT NULL REFERENCES users(username),
                level INTEGER NOT NULL,
                solved_at TIMESTAMP DEFAULT NOW(),
                UNIQUE(username, level)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS level_timers (
                id SERIAL PRIMARY KEY,
                username VARCHAR(20) NOT NULL REFERENCES users(username),
                level INTEGER NOT NULL,
                started_at TIMESTAMP NOT NULL DEFAULT NOW(),
                finished_at TIMESTAMP,
                elapsed_seconds FLOAT,
                UNIQUE(username, level)
            )
        """)
        # Add consent column if missing (safe to re-run)
        cur.execute("""
            DO $$ BEGIN
                ALTER TABLE users ADD COLUMN consent BOOLEAN DEFAULT FALSE;
            EXCEPTION WHEN duplicate_column THEN NULL;
            END $$;
        """)


# ---------------------------------------------------------------------------
# Core: per-user seeded flag generation
# ---------------------------------------------------------------------------

def get_user_rng(username: str, level: int) -> random.Random:
    """Return a seeded RNG unique to (username, level)."""
    combined = f'{username.lower().strip()}:level{level}:ri-comp-salt'
    seed = int(hashlib.sha256(combined.encode()).hexdigest(), 16) % (2**32)
    return random.Random(seed)


def generate_flag(username: str, level: int) -> str:
    rng = get_user_rng(username, level)
    body = ''.join(rng.choices(string.ascii_uppercase + string.digits, k=12))
    return f'FLAG{{{body}}}'


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def user_exists(username: str) -> bool:
    with get_db() as (conn, cur):
        cur.execute("SELECT 1 FROM users WHERE username = %s", (username,))
        return cur.fetchone() is not None


def create_user(username: str):
    with get_db() as (conn, cur):
        cur.execute("INSERT INTO users (username) VALUES (%s)", (username,))


def get_user_solves(username: str) -> dict:
    """Return {level_num: solved_at_timestamp} for a user."""
    with get_db() as (conn, cur):
        cur.execute(
            "SELECT level, solved_at FROM solves WHERE username = %s",
            (username,)
        )
        return {row['level']: row['solved_at'].timestamp() for row in cur.fetchall()}


def record_solve(username: str, level: int):
    with get_db() as (conn, cur):
        cur.execute(
            "INSERT INTO solves (username, level) VALUES (%s, %s) ON CONFLICT DO NOTHING",
            (username, level)
        )


def start_timer(username: str, level: int):
    """Record when a user first opens a level. No-op if already started."""
    with get_db() as (conn, cur):
        cur.execute(
            """INSERT INTO level_timers (username, level, started_at)
               VALUES (%s, %s, NOW())
               ON CONFLICT (username, level) DO NOTHING""",
            (username, level)
        )


def stop_timer(username: str, level: int):
    """Stop the timer for a level and record elapsed seconds."""
    with get_db() as (conn, cur):
        cur.execute(
            """UPDATE level_timers
               SET finished_at = NOW(),
                   elapsed_seconds = EXTRACT(EPOCH FROM (NOW() - started_at))
               WHERE username = %s AND level = %s AND finished_at IS NULL""",
            (username, level)
        )


def get_timer_info(username: str, level: int):
    """Return (elapsed_seconds, is_finished) for a level timer."""
    with get_db() as (conn, cur):
        cur.execute(
            """SELECT started_at, finished_at, elapsed_seconds,
                      EXTRACT(EPOCH FROM (NOW() - started_at)) AS running_seconds
               FROM level_timers WHERE username = %s AND level = %s""",
            (username, level)
        )
        row = cur.fetchone()
        if not row:
            return None, False
        if row['finished_at'] is not None:
            return row['elapsed_seconds'], True
        return row['running_seconds'], False


def get_scoreboard():
    with get_db() as (conn, cur):
        cur.execute("""
            SELECT u.username,
                   ARRAY_AGG(s.level ORDER BY s.level) AS solved,
                   COUNT(s.level) AS count,
                   MAX(s.solved_at) AS last_time,
                   COALESCE((SELECT SUM(lt.elapsed_seconds)
                             FROM level_timers lt
                             WHERE lt.username = u.username
                               AND lt.finished_at IS NOT NULL), 0) AS total_seconds
            FROM users u
            LEFT JOIN solves s ON u.username = s.username
            GROUP BY u.username
            HAVING COUNT(s.level) > 0
            ORDER BY COUNT(s.level) DESC, MAX(s.solved_at) ASC
        """)
        return cur.fetchall()


# ---------------------------------------------------------------------------
# Auth helper
# ---------------------------------------------------------------------------

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Level 2 helpers: Cookie manipulation
# ---------------------------------------------------------------------------

def _make_access_cookie(username: str, role: str = 'guest') -> str:
    """Create a base64-encoded JSON access cookie."""
    payload = {'user': username, 'role': role, 'ts': 1742000000}
    return base64.b64encode(_json.dumps(payload, separators=(',', ':')).encode()).decode()


def _parse_access_cookie(cookie_val: str) -> dict | None:
    """Decode and parse the access cookie. Returns None on failure."""
    try:
        decoded = base64.b64decode(cookie_val).decode()
        return _json.loads(decoded)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Level 3 helpers: JS obfuscation
# ---------------------------------------------------------------------------

_XOR_KEY = "RICOMP"


def _xor_encode_flag(flag: str) -> list[int]:
    """XOR each character of the flag with repeating key."""
    return [ord(c) ^ ord(_XOR_KEY[i % len(_XOR_KEY)]) for i, c in enumerate(flag)]


def generate_obfuscated_js(username: str) -> str:
    """Generate obfuscated JS containing the user's Level 3 flag."""
    flag = generate_flag(username, 3)
    xored = _xor_encode_flag(flag)
    hex_str = ''.join(f'{b:02x}' for b in xored)

    # Split hex string into 4-char chunks
    chunks = [hex_str[i:i+4] for i in range(0, len(hex_str), 4)]
    n = len(chunks)

    # Create a scrambled order
    rng = get_user_rng(username, 3)
    rng.choices(string.ascii_uppercase + string.digits, k=12)  # consume flag RNG
    order = list(range(n))
    rng.shuffle(order)

    # Build scrambled array: scrambled[order[i]] = chunks[i]
    scrambled = [''] * n
    for i, idx in enumerate(order):
        scrambled[idx] = chunks[i]

    # XOR key as char codes
    key_codes = [ord(c) for c in _XOR_KEY]

    js = f"""// RI-COMP Security Module v3.7.2
// Integrity verification system - DO NOT MODIFY
(function() {{
    var _0x4f3a = "R0lGT1JNQVQ=";
    var _0x9c2e = "aW50ZWdyaXR5";
    var _0x1d7b = [{', '.join(f'"{c}"' for c in scrambled)}];
    var _0x8a4f = [{', '.join(str(x) for x in order)}];
    var _0xf1 = [{', '.join(str(c) for c in key_codes)}];
    var _0x3377 = "session_valid";

    function _0xa1(t) {{ return atob(t); }}
    function _0xb2(a, b) {{ return a ^ b; }}

    function _0xcc() {{
        var _r = "";
        for (var i = 0; i < _0x8a4f.length; i++) {{
            _r += _0x1d7b[_0x8a4f[i]];
        }}
        return _r;
    }}

    function _0x7e(_hex) {{
        var out = "";
        for (var j = 0; j < _hex.length; j += 2) {{
            out += String.fromCharCode(
                _0xb2(parseInt(_hex.substr(j, 2), 16), _0xf1[(j / 2) % _0xf1.length])
            );
        }}
        return out;
    }}

    function _0xe5() {{
        try {{
            var _p = _0xa1(_0x4f3a);
            if (_p.indexOf("GIF") !== -1) return false;
        }} catch(e) {{}}
        return true;
    }}

    function _verify() {{
        if (!_0xe5()) return _0x3377;
        return _0x7e(_0xcc());
    }}

    // Module self-check
    var _status = _0xe5();
    console.log("%c[Security Module] " + (_status ? "Active" : "Error"), "color: #0f0; font-weight: bold;");

    // Debug hook - remove before production
    if (window.__RICOMP_DEBUG) {{
        console.log(_verify());
    }}
}})();"""

    return js


# ---------------------------------------------------------------------------
# Level 4 helpers: Caesar cipher
# ---------------------------------------------------------------------------

def get_caesar_shift(username: str) -> int:
    rng = get_user_rng(username, 4)
    rng.choices(string.ascii_uppercase + string.digits, k=12)  # consume flag RNG
    return rng.randint(1, 25)


def caesar_encrypt(text: str, shift: int) -> str:
    result = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            result.append(ch)
    return ''.join(result)


# ---------------------------------------------------------------------------
# Level 5 helpers: JWT
# ---------------------------------------------------------------------------

def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def _b64url_decode(s: str) -> bytes:
    """Base64url decode with padding restoration."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += '=' * padding
    return base64.urlsafe_b64decode(s)


def get_jwt_secret(username: str) -> str:
    """Per-user JWT secret for Level 5."""
    rng = get_user_rng(username, 5)
    rng.choices(string.ascii_uppercase + string.digits, k=12)  # consume flag RNG
    return ''.join(rng.choices(string.ascii_lowercase + string.digits, k=24))


def verify_jwt(token: str, secret: str) -> dict | None:
    """Verify a HS256 JWT and return the payload, or None."""
    parts = token.split('.')
    if len(parts) != 3:
        return None

    header_b64, payload_b64, sig_b64 = parts

    try:
        header = _json.loads(_b64url_decode(header_b64))
        if header.get('alg') != 'HS256':
            return None
    except Exception:
        return None

    signing_input = f'{header_b64}.{payload_b64}'.encode()
    expected_sig = _hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    expected_sig_b64 = _b64url_encode(expected_sig)

    if expected_sig_b64 != sig_b64:
        return None

    try:
        payload = _json.loads(_b64url_decode(payload_b64))
        return payload
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Level 6 helpers: Timing side-channel
# ---------------------------------------------------------------------------

TIMING_DELAY = 0.075  # 75ms per correct character


# ---------------------------------------------------------------------------
# Level info
# ---------------------------------------------------------------------------

LEVEL_INFO = [
    {'num': 1, 'title': 'Hidden in Plain Sight', 'difficulty': 'Easy'},
    {'num': 2, 'title': 'Privilege Escalation',  'difficulty': 'Easy-Medium'},
    {'num': 3, 'title': 'Codebreaker',           'difficulty': 'Medium'},
    {'num': 4, 'title': 'Cipher',                'difficulty': 'Medium'},
    {'num': 5, 'title': 'Shadow Protocol',       'difficulty': 'Hard'},
    {'num': 6, 'title': 'Phantom Signal',        'difficulty': 'Very Hard'},
]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        if not username or len(username) > 20:
            return render_template('index.html', error='Handle must be 1-20 characters.')
        if not re.match(r'^[a-z0-9_]+$', username):
            return render_template('index.html', error='Only lowercase letters, digits, and underscores.')

        existing = user_exists(username)
        if not existing:
            consent = request.form.get('consent')
            if not consent:
                return render_template('index.html',
                                       error='You must consent to data processing to participate.',
                                       username_val=username)
            create_user(username)

        session['username'] = username
        resp = make_response(redirect(url_for('hub')))
        resp.delete_cookie('access')
        resp.delete_cookie('role')
        return resp
    return render_template('index.html')


@app.route('/hub')
@login_required
def hub():
    username = session['username']
    user_solves = get_user_solves(username)
    levels = []
    for info in LEVEL_INFO:
        levels.append({**info, 'solved': info['num'] in user_solves})
    all_solved = len(user_solves) == 6
    return render_template('hub.html', levels=levels, all_solved=all_solved)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


# ---------------------------------------------------------------------------
# Level 1: Hidden in Plain Sight (flag in HTML source)
# ---------------------------------------------------------------------------

@app.route('/level/1')
@login_required
def level1():
    username = session['username']
    start_timer(username, 1)
    timer_elapsed, timer_done = get_timer_info(username, 1)
    flag = generate_flag(username, 1)
    return render_template('level1.html', flag=flag,
                           timer_elapsed=timer_elapsed,
                           timer_done=timer_done)


# ---------------------------------------------------------------------------
# Level 2: Cookie manipulation
# ---------------------------------------------------------------------------

@app.route('/level/2')
@login_required
def level2():
    username = session['username']
    start_timer(username, 2)
    timer_elapsed, timer_done = get_timer_info(username, 2)
    access_cookie = request.cookies.get('access', '')
    parsed = _parse_access_cookie(access_cookie) if access_cookie else None

    role = 'guest'
    if parsed and parsed.get('role') == 'admin':
        role = 'admin'

    flag = generate_flag(username, 2) if role == 'admin' else None
    cookie_display = access_cookie if access_cookie else '(not set)'

    resp = make_response(render_template(
        'level2.html', role=role, flag=flag,
        cookie_raw=cookie_display, cookie_decoded=parsed,
        timer_elapsed=timer_elapsed,
        timer_done=timer_done
    ))
    if not access_cookie:
        resp.set_cookie('access', _make_access_cookie(username, 'guest'))
    return resp


# ---------------------------------------------------------------------------
# Level 3: JavaScript obfuscation
# ---------------------------------------------------------------------------

@app.route('/level/3')
@login_required
def level3():
    username = session['username']
    start_timer(username, 3)
    timer_elapsed, timer_done = get_timer_info(username, 3)
    obfuscated_js = generate_obfuscated_js(username)
    return render_template('level3.html', obfuscated_js=obfuscated_js,
                           timer_elapsed=timer_elapsed,
                           timer_done=timer_done)


# ---------------------------------------------------------------------------
# Level 4: Caesar cipher
# ---------------------------------------------------------------------------

@app.route('/level/4')
@login_required
def level4():
    username = session['username']
    start_timer(username, 4)
    timer_elapsed, timer_done = get_timer_info(username, 4)
    flag = generate_flag(username, 4)
    shift = get_caesar_shift(username)
    encrypted = caesar_encrypt(flag, shift)
    return render_template('level4.html', encrypted=encrypted,
                           timer_elapsed=timer_elapsed,
                           timer_done=timer_done)


# ---------------------------------------------------------------------------
# Level 5: Multi-step chain (robots.txt -> debug config -> JWT forge -> vault)
# ---------------------------------------------------------------------------

@app.route('/level/5')
@login_required
def level5():
    username = session['username']
    start_timer(username, 5)
    timer_elapsed, timer_done = get_timer_info(username, 5)
    return render_template('level5.html',
                           timer_elapsed=timer_elapsed,
                           timer_done=timer_done)


@app.route('/robots.txt')
def robots_txt():
    content = """User-agent: *
Disallow: /debug/config
# NOTE: debug endpoints must not be indexed
"""
    return content, 200, {'Content-Type': 'text/plain'}


@app.route('/debug/config')
@login_required
def debug_config():
    username = session['username']
    secret = get_jwt_secret(username)
    return jsonify({
        'status': 'debug_active',
        'jwt_secret': secret,
        'jwt_algorithm': 'HS256',
        'note': 'Use this secret to sign a JWT. The vault requires role=admin in the payload.',
        'vault': '/api/vault',
        'jwt_format': 'Header: {"alg":"HS256","typ":"JWT"} | Payload must include: {"sub":"<username>","role":"admin"}'
    })


@app.route('/api/vault')
@login_required
def api_vault():
    username = session['username']
    auth_header = request.headers.get('Authorization', '')

    if not auth_header.startswith('Bearer '):
        return jsonify({
            'error': 'Authorization required',
            'hint': 'Send a Bearer token in the Authorization header'
        }), 401

    token = auth_header[7:]
    secret = get_jwt_secret(username)
    payload = verify_jwt(token, secret)

    if payload is None:
        return jsonify({'error': 'Invalid or tampered token'}), 403

    if payload.get('role') != 'admin':
        return jsonify({'error': 'Insufficient privileges. Admin role required.'}), 403

    if payload.get('sub') != username:
        return jsonify({'error': 'Token subject does not match session user.'}), 403

    flag = generate_flag(username, 5)
    return jsonify({
        'status': 'access_granted',
        'flag': flag,
        'message': 'Well done, agent. You cracked the Shadow Protocol.'
    })


# ---------------------------------------------------------------------------
# Level 6: Timing side-channel
# ---------------------------------------------------------------------------

@app.route('/level/6')
@login_required
def level6():
    username = session['username']
    start_timer(username, 6)
    timer_elapsed, timer_done = get_timer_info(username, 6)
    return render_template('level6.html',
                           timer_elapsed=timer_elapsed,
                           timer_done=timer_done)


@app.route('/level/6/signal', methods=['POST'])
@login_required
def level6_signal():
    """Verification endpoint with intentional timing side-channel."""
    username = session['username']
    flag = generate_flag(username, 6)
    guess = request.form.get('code', request.json.get('code', '') if request.is_json else '')

    # Intentional vulnerability: timing leak
    # Each correct character adds a delay before rejection
    matched = 0
    for i in range(min(len(guess), len(flag))):
        if guess[i] != flag[i]:
            break
        matched += 1
        time.sleep(TIMING_DELAY)

    return jsonify({'status': 'invalid', 'ts': int(time.time() * 1000)})


# ---------------------------------------------------------------------------
# Flag submission & scoreboard
# ---------------------------------------------------------------------------

@app.route('/submit', methods=['POST'])
@login_required
def submit_flag():
    username = session['username']
    try:
        level = int(request.form['level'])
    except (KeyError, ValueError):
        return redirect(url_for('hub'))

    submitted = request.form.get('flag', '').strip()
    expected = generate_flag(username, level)
    correct = submitted == expected

    if correct:
        stop_timer(username, level)
        record_solve(username, level)

    return render_template('success.html', level=level, correct=correct)


@app.route('/scoreboard')
def scoreboard_view():
    rows = get_scoreboard()
    board = []
    for row in rows:
        solved = row['solved'] if row['solved'] and row['solved'][0] is not None else []
        total_sec = row['total_seconds'] or 0
        hours = int(total_sec // 3600)
        minutes = int((total_sec % 3600) // 60)
        seconds = int(total_sec % 60)
        if hours > 0:
            time_str = f'{hours}h {minutes:02d}m {seconds:02d}s'
        elif minutes > 0:
            time_str = f'{minutes}m {seconds:02d}s'
        else:
            time_str = f'{seconds}s'
        board.append({
            'username': row['username'],
            'solved': solved,
            'count': row['count'],
            'last_time': row['last_time'].timestamp() if row['last_time'] else 0,
            'total_time': time_str,
            'total_seconds': total_sec
        })
    return render_template('scoreboard.html', board=board)


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

# Always init DB tables on import (needed for gunicorn/vercel in production)
try:
    init_db()
except Exception as e:
    print(f'Warning: Could not init DB on startup: {e}')

if __name__ == '__main__':
    print('\n  RI-COMP CTF Server')
    print('  http://localhost:5000')
    print('  Database: PostgreSQL on localhost:5433\n')
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
