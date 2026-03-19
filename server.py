"""
RI-COMP CTF Challenge Server
A self-contained CTF web app with 5 levels and per-user flag randomization.
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
from functools import wraps
from contextlib import contextmanager

import psycopg2
import psycopg2.extras
from flask import (
    Flask, session, redirect, url_for, request,
    render_template, jsonify, make_response
)

app = Flask(__name__)
app.secret_key = 'ri-comp-ctf-2026-s3cr3t-key'

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

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


def get_level4_shift(username: str) -> int:
    rng = get_user_rng(username, 4)
    rng.choices(string.ascii_uppercase + string.digits, k=12)
    return rng.randint(1, 25)


def get_level5_suffix(username: str) -> str:
    rng = get_user_rng(username, 5)
    rng.choices(string.ascii_uppercase + string.digits, k=12)
    return ''.join(rng.choices('0123456789abcdef', k=6))


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


def get_scoreboard():
    with get_db() as (conn, cur):
        cur.execute("""
            SELECT u.username,
                   ARRAY_AGG(s.level ORDER BY s.level) AS solved,
                   COUNT(s.level) AS count,
                   MAX(s.solved_at) AS last_time
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
# Cookie helpers (Level 3)
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


LEVEL_INFO = [
    {'num': 1, 'title': 'The Surface',          'difficulty': 'Easy'},
    {'num': 2, 'title': 'Network Whisper',         'difficulty': 'Easy-Medium'},
    {'num': 3, 'title': 'Privilege Escalation',   'difficulty': 'Medium'},
    {'num': 4, 'title': 'Cipher',                 'difficulty': 'Medium'},
    {'num': 5, 'title': 'Deep Recon',             'difficulty': 'Hard'},
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

        # Check if username is taken by someone else (or create new)
        if user_exists(username):
            # Username exists — let them log back in
            pass
        else:
            create_user(username)

        session['username'] = username
        resp = make_response(redirect(url_for('hub')))
        # Clear leftover cookies from previous users
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
    all_solved = len(user_solves) == 5
    return render_template('hub.html', levels=levels, all_solved=all_solved)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


# ---------------------------------------------------------------------------
# Level 1: HTML source inspection
# ---------------------------------------------------------------------------

@app.route('/level/1')
@login_required
def level1():
    flag = generate_flag(session['username'], 1)
    return render_template('level1.html', flag=flag)


# ---------------------------------------------------------------------------
# Level 2: HTTP response header inspection
# ---------------------------------------------------------------------------

@app.route('/level/2')
@login_required
def level2():
    username = session['username']
    flag = generate_flag(username, 2)
    resp = make_response(render_template('level2.html'))
    resp.headers['X-CTF-Flag'] = flag
    resp.headers['X-Server-Note'] = 'Nice catch, agent. Submit this flag.'
    return resp


# ---------------------------------------------------------------------------
# Level 3: Encoded cookie manipulation
# ---------------------------------------------------------------------------

@app.route('/level/3')
@login_required
def level3():
    username = session['username']
    access_cookie = request.cookies.get('access', '')
    parsed = _parse_access_cookie(access_cookie) if access_cookie else None

    role = 'guest'
    if parsed and parsed.get('role') == 'admin':
        role = 'admin'

    flag = generate_flag(username, 3) if role == 'admin' else None
    cookie_display = access_cookie if access_cookie else '(not set)'

    resp = make_response(render_template(
        'level3.html', role=role, flag=flag,
        cookie_raw=cookie_display, cookie_decoded=parsed
    ))
    if not access_cookie:
        resp.set_cookie('access', _make_access_cookie(username, 'guest'))
    return resp


# ---------------------------------------------------------------------------
# Level 4: Caesar cipher
# ---------------------------------------------------------------------------

@app.route('/level/4')
@login_required
def level4():
    username = session['username']
    flag = generate_flag(username, 4)
    shift = get_level4_shift(username)
    encrypted = caesar_encrypt(flag, shift)
    return render_template('level4.html', encrypted=encrypted)


# ---------------------------------------------------------------------------
# Level 5: Hidden API endpoint
# ---------------------------------------------------------------------------

@app.route('/level/5')
@login_required
def level5():
    return render_template('level5.html')


@app.route('/api/data')
def api_data():
    return jsonify({
        'status': 'ok',
        'system': 'RI-COMP CTF Data Service',
        'endpoints': ['/api/data', '/api/health'],
        'hint': 'Not all endpoints are listed here. Some are secret.',
        'debug': 'Authenticated users can retrieve their token at /api/token'
    })


@app.route('/api/health')
def api_health():
    return jsonify({'status': 'healthy', 'uptime': int(time.time())})


@app.route('/api/token')
@login_required
def api_token():
    suffix = get_level5_suffix(session['username'])
    return jsonify({
        'token': suffix,
        'usage': 'Append this token to the secret endpoint path'
    })


@app.route('/api/secret_<suffix>')
@login_required
def api_secret(suffix):
    username = session['username']
    expected = get_level5_suffix(username)
    if suffix == expected:
        flag = generate_flag(username, 5)
        return jsonify({'flag': flag, 'message': 'Well done, agent.'})
    return jsonify({'error': 'Unknown endpoint'}), 404


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
        record_solve(username, level)

    return render_template('success.html', level=level, correct=correct)


@app.route('/scoreboard')
def scoreboard_view():
    rows = get_scoreboard()
    board = []
    for row in rows:
        solved = row['solved'] if row['solved'] and row['solved'][0] is not None else []
        board.append({
            'username': row['username'],
            'solved': solved,
            'count': row['count'],
            'last_time': row['last_time'].timestamp() if row['last_time'] else 0
        })
    return render_template('scoreboard.html', board=board)


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    init_db()
    print('\n  RI-COMP CTF Server')
    print('  http://localhost:5000')
    print('  Database: PostgreSQL on localhost:5433\n')
    app.run(host='0.0.0.0', port=5000, debug=True)
