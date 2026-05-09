"""
LMRL — Lifelong Medical Records Ledger

Roles:
  admin   — full access + admin panel + user management
  doctor  — add/edit patients, records, prescriptions, timelines
  nurse   — same as doctor
  viewer  — sees ONLY their linked patient's data (read-only)

New in this version:
  • First registered user automatically becomes admin
  • Viewers must enter their Patient UID during registration
    and can ONLY view that one patient's records
  • Email OTP verification required on every new signup
    (Falls back to on-screen OTP if email is not configured)

Security:
  PBKDF2-SHA256 (260k iterations) · CSRF · Rate-limiting · Audit log
"""

from flask import (Flask, render_template, request, redirect, url_for,
                   flash, send_from_directory, session, abort, g)
import sqlite3, uuid, os, hashlib, hmac, secrets, time, random
import urllib.request, urllib.error, json
from functools import wraps
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta

# ── APP CONFIG ────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)

IS_RENDER  = bool(os.environ.get('RENDER'))
BASE_DIR   = '/tmp' if IS_RENDER else os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)

ALLOWED_EXT = {'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}
app.config['UPLOAD_FOLDER']      = UPLOAD_DIR
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
DB_PATH = os.path.join(BASE_DIR, 'lmrl.db')

# Email: uses Resend API (HTTPS) — works on Render free tier.
# Set RESEND_API_KEY and EMAIL_FROM in Render environment variables.

_login_attempts: dict = {}
MAX_ATTEMPTS  = 5
LOCKOUT_SECS  = 15 * 60
OTP_EXPIRY    = 10 * 60   # 10 minutes

WRITE_ROLES = ('admin', 'doctor', 'nurse')

# ── DATABASE ──────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    conn = get_db()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT    NOT NULL UNIQUE,
            email         TEXT    NOT NULL UNIQUE,
            password_hash TEXT    NOT NULL,
            salt          TEXT    NOT NULL,
            role          TEXT    NOT NULL DEFAULT 'viewer',
            is_active     INTEGER NOT NULL DEFAULT 1,
            is_verified   INTEGER NOT NULL DEFAULT 0,
            patient_id    TEXT,
            otp_code      TEXT,
            otp_expires   REAL,
            created_at    TEXT    DEFAULT CURRENT_TIMESTAMP,
            last_login    TEXT,
            reset_token   TEXT,
            reset_expires REAL,
            FOREIGN KEY (patient_id) REFERENCES patients(id)
        );
        CREATE TABLE IF NOT EXISTS patients (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            dob         TEXT NOT NULL,
            gender      TEXT,
            blood_group TEXT,
            phone       TEXT,
            email       TEXT,
            address     TEXT,
            created_by  INTEGER REFERENCES users(id),
            created_at  TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS records (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id  TEXT NOT NULL REFERENCES patients(id),
            visit_date  TEXT NOT NULL,
            provider    TEXT,
            diagnosis   TEXT,
            notes       TEXT,
            file_path   TEXT,
            created_by  INTEGER REFERENCES users(id),
            created_at  TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS prescriptions (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id    TEXT NOT NULL REFERENCES patients(id),
            record_id     INTEGER REFERENCES records(id),
            drug_name     TEXT NOT NULL,
            dosage        TEXT,
            frequency     TEXT,
            duration      TEXT,
            notes         TEXT,
            prescribed_on TEXT,
            created_by    INTEGER REFERENCES users(id),
            created_at    TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS timelines (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id  TEXT NOT NULL REFERENCES patients(id),
            event_date  TEXT NOT NULL,
            event_type  TEXT,
            title       TEXT NOT NULL,
            description TEXT,
            created_at  TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER REFERENCES users(id),
            username   TEXT,
            action     TEXT NOT NULL,
            target     TEXT,
            ip         TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    ''')
    # Migration: add new columns if they don't exist yet (safe to run multiple times)
    for migration in [
        "ALTER TABLE users ADD COLUMN reset_token   TEXT",
        "ALTER TABLE users ADD COLUMN reset_expires REAL",
    ]:
        try:
            conn.execute(migration)
            conn.commit()
        except Exception:
            pass  # column already exists

    conn.commit()
    conn.close()

# ── EMAIL OTP ─────────────────────────────────────────────────────────────────
def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_email(to_email: str, username: str, otp: str) -> bool:
    """
    Send OTP via Resend API (HTTPS) — works on Render free tier.
    Falls back gracefully if not configured.
    """
    api_key    = os.environ.get('RESEND_API_KEY', '').strip()
    email_from = os.environ.get('EMAIL_FROM', 'onboarding@resend.dev').strip()

    print(f"[EMAIL] to={to_email} api_key_set={bool(api_key)} from={email_from}", flush=True)

    if not api_key:
        print("[EMAIL] RESEND_API_KEY not set — falling back to on-screen OTP", flush=True)
        return False

    html_body = f"""
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:24px;background:#f5f6fa;border-radius:12px">
      <div style="background:#4f6ef7;border-radius:10px;padding:20px 24px;text-align:center;margin-bottom:20px">
        <div style="font-size:32px">&#9877;</div>
        <div style="color:#fff;font-size:18px;font-weight:700;margin-top:6px">LMRL Verification</div>
      </div>
      <div style="background:#fff;border-radius:10px;padding:24px;border:1px solid #e2e5f0">
        <p style="color:#1a1d2e;font-size:15px;margin-bottom:16px">Hi <strong>{username}</strong>,</p>
        <p style="color:#4a5068;font-size:14px;margin-bottom:20px">Your one-time verification code is:</p>
        <div style="background:#eef1fe;border:2px dashed #4f6ef7;border-radius:10px;padding:20px;text-align:center;margin-bottom:20px">
          <div style="font-size:36px;font-weight:700;letter-spacing:10px;color:#4f6ef7;font-family:monospace">{otp}</div>
        </div>
        <p style="color:#8b91a7;font-size:13px">Expires in <strong>10 minutes</strong>. Do not share it.</p>
      </div>
    </div>
    """

    payload = json.dumps({
        "from":    email_from,
        "to":      [to_email],
        "subject": f"Your LMRL Verification Code: {otp}",
        "html":    html_body,
        "text":    f"Hi {username},\n\nYour LMRL OTP is: {otp}\n\nExpires in 10 minutes.",
    }).encode('utf-8')

    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data    = payload,
        method  = "POST",
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type":  "application/json",
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode()
            print(f"[EMAIL] Resend API response {resp.status}: {body}", flush=True)
            return resp.status in (200, 201)
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"[EMAIL] Resend HTTP {e.code}: {body}", flush=True)
        return False
    except Exception as e:
        print(f"[EMAIL] Error: {type(e).__name__}: {e}", flush=True)
        return False


def hash_password(password, salt=None):
    if not salt:
        salt = secrets.token_hex(32)
    h = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 260_000)
    return h.hex(), salt

def verify_password(password, stored_hash, salt):
    computed, _ = hash_password(password, salt)
    return hmac.compare_digest(computed, stored_hash)

def gen_csrf():
    if '_csrf' not in session:
        session['_csrf'] = secrets.token_hex(32)
    return session['_csrf']

def check_csrf():
    token = request.form.get('_csrf_token', '')
    if not token or not hmac.compare_digest(token, session.get('_csrf', '')):
        audit('CSRF_FAIL', request.path)
        abort(403)

def client_ip():
    return (request.headers.get('X-Forwarded-For', '') or request.remote_addr or '').split(',')[0].strip()

def is_rate_limited(ip):
    now = time.time()
    attempts = [t for t in _login_attempts.get(ip, []) if now - t < LOCKOUT_SECS]
    _login_attempts[ip] = attempts
    if len(attempts) >= MAX_ATTEMPTS:
        return True, int(LOCKOUT_SECS - (now - attempts[0]))
    return False, 0

def record_attempt(ip):
    _login_attempts.setdefault(ip, []).append(time.time())

def clear_attempts(ip):
    _login_attempts.pop(ip, None)

def audit(action, target=None):
    try:
        conn = get_db()
        conn.execute(
            'INSERT INTO audit_log (user_id,username,action,target,ip) VALUES (?,?,?,?,?)',
            (session.get('user_id'), session.get('username'), action, target, client_ip()))
        conn.commit()
        conn.close()
    except Exception:
        pass

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT

def get_current_user():
    if 'user_id' in session:
        conn = get_db()
        u = conn.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone()
        conn.close()
        return u
    return None

def viewer_patient_id():
    """Return the patient_id a viewer is restricted to, or None if not a viewer."""
    if session.get('role') == 'viewer':
        return session.get('viewer_pid')
    return None

# ── DECORATORS ────────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def d(*a, **kw):
        if 'user_id' not in session:
            flash('Please log in to continue.', 'error')
            return redirect(url_for('login'))
        return f(*a, **kw)
    return d

def write_required(f):
    @wraps(f)
    def d(*a, **kw):
        if 'user_id' not in session:
            flash('Please log in.', 'error')
            return redirect(url_for('login'))
        if session.get('role') not in WRITE_ROLES:
            audit('WRITE_DENIED', request.path)
            flash('View-only access — you cannot modify data.', 'error')
            abort(403)
        return f(*a, **kw)
    return d

def admin_required(f):
    @wraps(f)
    def d(*a, **kw):
        if 'user_id' not in session:
            flash('Please log in.', 'error')
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            audit('ADMIN_DENIED', request.path)
            flash('Admins only.', 'error')
            abort(403)
        return f(*a, **kw)
    return d

# ── CONTEXT PROCESSOR ─────────────────────────────────────────────────────────
@app.context_processor
def inject_globals():
    u = get_current_user()
    return {
        'current_user': u,
        'csrf_token':   gen_csrf(),
        'can_write':    u and u['role'] in WRITE_ROLES,
        'is_admin':     u and u['role'] == 'admin',
        'is_viewer':    u and u['role'] == 'viewer',
    }

@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', code=403,
        msg="You don't have permission to access this page."), 403

@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', code=404,
        msg="The page you're looking for doesn't exist."), 404

# ═══════════════════════════════════════════════════════════════════════
#  REGISTRATION & OTP
# ═══════════════════════════════════════════════════════════════════════
@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        check_csrf()
        username   = request.form.get('username', '').strip()
        email      = request.form.get('email', '').strip().lower()
        password   = request.form.get('password', '')
        confirm    = request.form.get('confirm_password', '')
        patient_id = request.form.get('patient_id', '').strip()

        conn = get_db()

        # Check if this is the very first user BEFORE validation
        # so we can skip the Patient UID requirement for the admin
        user_count = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
        is_first_user = (user_count == 0)

        # First user becomes admin automatically — no patient UID needed
        if is_first_user:
            role = 'admin'
            patient_id = None
        else:
            role = 'viewer'

        # Validation
        errs = []
        if not all([username, email, password]):
            errs.append('All fields are required.')
        if len(username) < 3:
            errs.append('Username must be at least 3 characters.')
        if len(password) < 8:
            errs.append('Password must be at least 8 characters.')
        if password != confirm:
            errs.append('Passwords do not match.')
        if not is_first_user and not patient_id:
            errs.append('Please provide your Patient UID to link your account.')
        if errs:
            conn.close()
            for e in errs: flash(e, 'error')
            return render_template('register.html', is_first_user=is_first_user)

        # For viewers: verify the patient UID actually exists
        if not is_first_user:
            pat = conn.execute('SELECT id FROM patients WHERE id=?', (patient_id,)).fetchone()
            if not pat:
                conn.close()
                flash('Patient UID not found. Please ask your doctor for the correct UID.', 'error')
                return render_template('register.html', is_first_user=False)

        # Check duplicate username/email
        if conn.execute('SELECT id FROM users WHERE username=? OR email=?',
                        (username, email)).fetchone():
            conn.close()
            flash('Username or email already taken.', 'error')
            return render_template('register.html', is_first_user=is_first_user)

        # Generate OTP
        otp      = generate_otp()
        otp_exp  = time.time() + OTP_EXPIRY
        pwd_hash, salt = hash_password(password)

        # Create unverified user
        conn.execute(
            '''INSERT INTO users
               (username,email,password_hash,salt,role,is_verified,patient_id,otp_code,otp_expires)
               VALUES (?,?,?,?,?,0,?,?,?)''',
            (username, email, pwd_hash, salt, role,
             patient_id if role == 'viewer' else None,
             otp, otp_exp))
        conn.commit()
        uid = conn.execute('SELECT id FROM users WHERE username=?', (username,)).fetchone()['id']
        conn.close()

        # Try to send OTP email
        email_sent = send_otp_email(email, username, otp)

        # Store pending verification in session
        session['pending_verify_uid'] = uid
        session['pending_verify_user'] = username

        if email_sent:
            flash(f'A 6-digit OTP has been sent to {email}. It expires in 10 minutes.', 'success')
            return redirect(url_for('verify_otp'))
        else:
            # Email not configured → show OTP on screen (dev mode)
            flash(f'Email not configured. Your OTP is: {otp} (shown for development only)', 'error')
            return redirect(url_for('verify_otp'))

    # Pass is_first_user so template can hide/show Patient UID field
    conn = get_db()
    is_first_user = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0] == 0
    conn.close()
    return render_template('register.html', is_first_user=is_first_user)


@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    uid = session.get('pending_verify_uid')
    if not uid:
        flash('No pending verification. Please register first.', 'error')
        return redirect(url_for('register'))

    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
    if not user:
        conn.close()
        flash('User not found. Please register again.', 'error')
        return redirect(url_for('register'))

    if request.method == 'POST':
        check_csrf()
        action = request.form.get('action', 'verify')

        if action == 'resend':
            # Resend OTP
            new_otp = generate_otp()
            new_exp = time.time() + OTP_EXPIRY
            conn.execute('UPDATE users SET otp_code=?,otp_expires=? WHERE id=?',
                         (new_otp, new_exp, uid))
            conn.commit()
            conn.close()
            sent = send_otp_email(user['email'], user['username'], new_otp)
            if sent:
                flash('A new OTP has been sent to your email.', 'success')
            else:
                flash(f'Email not configured. New OTP: {new_otp}', 'error')
            return redirect(url_for('verify_otp'))

        entered = request.form.get('otp', '').strip()
        now     = time.time()

        if not entered:
            conn.close()
            flash('Please enter the OTP.', 'error')
            return render_template('verify_otp.html', username=user['username'], email=user['email'])

        if user['otp_expires'] and now > user['otp_expires']:
            conn.close()
            flash('OTP has expired. Please request a new one.', 'error')
            return render_template('verify_otp.html', username=user['username'], email=user['email'])

        if not hmac.compare_digest(entered, str(user['otp_code'])):
            conn.close()
            flash('Incorrect OTP. Please try again.', 'error')
            return render_template('verify_otp.html', username=user['username'], email=user['email'])

        # ✅ OTP verified — activate account
        conn.execute('UPDATE users SET is_verified=1,otp_code=NULL,otp_expires=NULL WHERE id=?', (uid,))
        conn.commit()
        conn.close()

        audit('EMAIL_VERIFIED', user['username'])
        session.pop('pending_verify_uid', None)
        session.pop('pending_verify_user', None)

        role_label = user['role']
        if user['role'] == 'admin':
            flash(f'Email verified! Welcome, {user["username"]}. You are the first user and have been given Admin access. Please log in.', 'success')
        else:
            flash(f'Email verified! Account created as {role_label.title()}. Please log in.', 'success')
        return redirect(url_for('login'))

    conn.close()
    return render_template('verify_otp.html', username=user['username'], email=user['email'])


# ═══════════════════════════════════════════════════════════════════════
#  LOGIN / LOGOUT
# ═══════════════════════════════════════════════════════════════════════
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        check_csrf()
        ip = client_ip()
        locked, remaining = is_rate_limited(ip)
        if locked:
            flash(f'Too many failed attempts. Try again in {remaining//60} min.', 'error')
            return render_template('login.html')

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        conn = get_db()
        user = conn.execute(
            'SELECT * FROM users WHERE (username=? OR email=?) AND is_active=1',
            (username, username)).fetchone()
        conn.close()

        if not user:
            record_attempt(ip)
            left = max(0, MAX_ATTEMPTS - len(_login_attempts.get(ip, [])))
            audit('LOGIN_FAIL', username)
            flash(f'Invalid credentials. {left} attempts remaining.', 'error')
            return render_template('login.html')

        if not user['is_verified']:
            # Account exists but not verified → redirect to OTP
            session['pending_verify_uid']  = user['id']
            session['pending_verify_user'] = user['username']
            flash('Your account is not verified yet. Please complete OTP verification.', 'error')
            return redirect(url_for('verify_otp'))

        if verify_password(password, user['password_hash'], user['salt']):
            clear_attempts(ip)
            session.permanent = False
            session['user_id']  = user['id']
            session['username'] = user['username']
            session['role']     = user['role']
            if user['role'] == 'viewer' and user['patient_id']:
                session['viewer_pid'] = user['patient_id']

            conn = get_db()
            conn.execute('UPDATE users SET last_login=? WHERE id=?',
                         (datetime.utcnow().isoformat(), user['id']))
            conn.commit()
            conn.close()
            audit('LOGIN', username)
            flash(f'Welcome back, {user["username"]}!', 'success')

            # Redirect viewer straight to their patient
            if user['role'] == 'viewer' and user['patient_id']:
                return redirect(url_for('patient_detail', pid=user['patient_id']))
            return redirect(url_for('index'))
        else:
            record_attempt(ip)
            left = max(0, MAX_ATTEMPTS - len(_login_attempts.get(ip, [])))
            audit('LOGIN_FAIL', username)
            flash(f'Invalid credentials. {left} attempts remaining.', 'error')

    return render_template('login.html')


@app.route('/logout')
def logout():
    audit('LOGOUT')
    session.clear()
    flash('You have been securely logged out.', 'success')
    return redirect(url_for('login'))


# ═══════════════════════════════════════════════════════════════════════
#  PROFILE
# ═══════════════════════════════════════════════════════════════════════
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = get_current_user()
    if request.method == 'POST':
        check_csrf()
        action = request.form.get('action')
        conn = get_db()
        if action == 'update_email':
            email = request.form.get('email', '').strip().lower()
            conn.execute('UPDATE users SET email=? WHERE id=?', (email, user['id']))
            conn.commit()
            audit('UPDATE_EMAIL')
            flash('Email updated.', 'success')
        elif action == 'change_password':
            cur = request.form.get('current_password', '')
            new = request.form.get('new_password', '')
            cfm = request.form.get('confirm_password', '')
            if not verify_password(cur, user['password_hash'], user['salt']):
                flash('Current password is incorrect.', 'error')
            elif len(new) < 8:
                flash('New password must be at least 8 characters.', 'error')
            elif new != cfm:
                flash('Passwords do not match.', 'error')
            else:
                h, s = hash_password(new)
                conn.execute('UPDATE users SET password_hash=?,salt=? WHERE id=?', (h, s, user['id']))
                conn.commit()
                audit('CHANGE_PASSWORD')
                flash('Password changed successfully.', 'success')
        conn.close()
        return redirect(url_for('profile'))

    conn = get_db()
    mp = conn.execute('SELECT COUNT(*) FROM patients WHERE created_by=?', (user['id'],)).fetchone()[0]
    mr = conn.execute('SELECT COUNT(*) FROM records  WHERE created_by=?', (user['id'],)).fetchone()[0]
    linked_patient = None
    if user['role'] == 'viewer' and user['patient_id']:
        linked_patient = conn.execute('SELECT * FROM patients WHERE id=?',
                                      (user['patient_id'],)).fetchone()
    conn.close()
    return render_template('profile.html', user=user,
                           my_patients=mp, my_records=mr, linked_patient=linked_patient)


# ═══════════════════════════════════════════════════════════════════════
#  ADMIN PANEL
# ═══════════════════════════════════════════════════════════════════════
@app.route('/admin')
@admin_required
def admin_panel():
    conn = get_db()
    users = conn.execute('SELECT * FROM users ORDER BY created_at DESC').fetchall()
    stats = {
        'users':    conn.execute('SELECT COUNT(*) FROM users').fetchone()[0],
        'patients': conn.execute('SELECT COUNT(*) FROM patients').fetchone()[0],
        'records':  conn.execute('SELECT COUNT(*) FROM records').fetchone()[0],
        'rx':       conn.execute('SELECT COUNT(*) FROM prescriptions').fetchone()[0],
    }
    logs = conn.execute('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 120').fetchall()
    conn.close()
    audit('ADMIN_VIEW')
    return render_template('admin_panel.html', users=users, stats=stats, logs=logs)


@app.route('/admin/test-email', methods=['POST'])
@admin_required
def admin_test_email():
    """Send a test email so admin can verify SMTP settings work."""
    check_csrf()
    user = get_current_user()
    test_otp = '123456'
    sent = send_otp_email(user['email'], user['username'], test_otp)
    if sent:
        flash(f'✅ Test email sent to {user["email"]}! Check your inbox.', 'success')
    else:
        email_user = os.environ.get('EMAIL_USER', '').strip()
        email_pass = os.environ.get('EMAIL_PASSWORD', '').strip()
        if not email_user:
            flash('❌ EMAIL_USER environment variable is empty or not set on Render.', 'error')
        elif not email_pass:
            flash('❌ EMAIL_PASSWORD environment variable is empty or not set on Render.', 'error')
        else:
            flash(f'❌ Email failed. EMAIL_USER={email_user} is set but sending failed — check Render logs for details.', 'error')
    return redirect(url_for('admin_panel'))


@app.route('/admin/user/<int:uid>/toggle', methods=['POST'])
@admin_required
def admin_toggle(uid):
    check_csrf()
    if uid == session['user_id']:
        flash("You can't deactivate yourself.", 'error')
        return redirect(url_for('admin_panel'))
    conn = get_db()
    u = conn.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
    if u:
        ns = 0 if u['is_active'] else 1
        conn.execute('UPDATE users SET is_active=? WHERE id=?', (ns, uid))
        conn.commit()
        audit(f'USER_{"ENABLED" if ns else "DISABLED"}', u['username'])
        flash(f'User "{u["username"]}" {"enabled" if ns else "disabled"}.', 'success')
    conn.close()
    return redirect(url_for('admin_panel'))

@app.route('/admin/user/<int:uid>/role', methods=['POST'])
@admin_required
def admin_role(uid):
    check_csrf()
    new_role = request.form.get('role', 'viewer')
    if new_role not in ('admin', 'doctor', 'nurse', 'viewer'):
        flash('Invalid role.', 'error')
        return redirect(url_for('admin_panel'))
    conn = get_db()
    u = conn.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
    if u:
        conn.execute('UPDATE users SET role=? WHERE id=?', (new_role, uid))
        conn.commit()
        audit('ROLE_CHANGE', f'{u["username"]} → {new_role}')
        flash(f'Role updated to "{new_role}" for {u["username"]}.', 'success')
    conn.close()
    return redirect(url_for('admin_panel'))

@app.route('/admin/user/<int:uid>/delete', methods=['POST'])
@admin_required
def admin_delete(uid):
    check_csrf()
    if uid == session['user_id']:
        flash("You can't delete yourself.", 'error')
        return redirect(url_for('admin_panel'))
    conn = get_db()
    u = conn.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
    if u:
        # Nullify FK references so delete doesn't violate constraints
        conn.execute('UPDATE patients       SET created_by=NULL WHERE created_by=?', (uid,))
        conn.execute('UPDATE records        SET created_by=NULL WHERE created_by=?', (uid,))
        conn.execute('UPDATE prescriptions  SET created_by=NULL WHERE created_by=?', (uid,))
        conn.execute('DELETE FROM users WHERE id=?', (uid,))
        conn.commit()
        audit('USER_DELETED', u['username'])
        flash(f'User "{u["username"]}" deleted.', 'success')
    conn.close()
    return redirect(url_for('admin_panel'))


@app.route('/admin/add-staff', methods=['POST'])
@admin_required
def admin_add_staff():
    """Admin creates a doctor or nurse account directly — no OTP, auto-verified."""
    check_csrf()
    username = request.form.get('username', '').strip()
    email    = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')
    role     = request.form.get('role', 'doctor')

    if role not in ('doctor', 'nurse'):
        flash('Invalid role. Must be doctor or nurse.', 'error')
        return redirect(url_for('admin_panel'))

    errs = []
    if not all([username, email, password]):
        errs.append('All fields are required.')
    if len(username) < 3:
        errs.append('Username must be at least 3 characters.')
    if len(password) < 8:
        errs.append('Password must be at least 8 characters.')
    if errs:
        for e in errs: flash(e, 'error')
        return redirect(url_for('admin_panel'))

    conn = get_db()
    if conn.execute('SELECT id FROM users WHERE username=? OR email=?',
                    (username, email)).fetchone():
        conn.close()
        flash('Username or email already taken.', 'error')
        return redirect(url_for('admin_panel'))

    pwd_hash, salt = hash_password(password)
    # is_verified=1 → admin-created accounts skip OTP
    conn.execute(
        '''INSERT INTO users (username,email,password_hash,salt,role,is_verified,is_active)
           VALUES (?,?,?,?,?,1,1)''',
        (username, email, pwd_hash, salt, role))
    conn.commit()
    conn.close()
    audit('ADMIN_ADD_STAFF', f'{role}:{username}')
    flash(f'{role.title()} account "{username}" created successfully. They can log in immediately.', 'success')
    return redirect(url_for('admin_panel'))


# ═══════════════════════════════════════════════════════════════════════
#  DOCTOR PANEL
# ═══════════════════════════════════════════════════════════════════════
@app.route('/doctor')
@write_required
def doctor_panel():
    uid = session['user_id']
    conn = get_db()
    my_patients = conn.execute(
        '''SELECT p.*, COUNT(r.id) as rc FROM patients p
           LEFT JOIN records r ON r.patient_id=p.id
           WHERE p.created_by=? GROUP BY p.id ORDER BY p.created_at DESC''', (uid,)
    ).fetchall()
    recent_records = conn.execute(
        '''SELECT r.*, p.name as pname FROM records r
           JOIN patients p ON r.patient_id=p.id
           WHERE r.created_by=? ORDER BY r.created_at DESC LIMIT 10''', (uid,)
    ).fetchall()
    recent_rx = conn.execute(
        '''SELECT pr.*, p.name as pname FROM prescriptions pr
           JOIN patients p ON pr.patient_id=p.id
           WHERE pr.created_by=? ORDER BY pr.created_at DESC LIMIT 8''', (uid,)
    ).fetchall()
    stats = {
        'patients': len(my_patients),
        'records':  conn.execute('SELECT COUNT(*) FROM records WHERE created_by=?', (uid,)).fetchone()[0],
        'rx':       conn.execute('SELECT COUNT(*) FROM prescriptions WHERE created_by=?', (uid,)).fetchone()[0],
    }
    conn.close()
    return render_template('doctor_panel.html', my_patients=my_patients,
                           recent_records=recent_records, recent_rx=recent_rx, stats=stats)




# ═══════════════════════════════════════════════════════════════════════
#  FORGOT / RESET PASSWORD
# ═══════════════════════════════════════════════════════════════════════
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        check_csrf()
        email = request.form.get('email', '').strip().lower()
        if not email:
            flash('Please enter your email address.', 'error')
            return render_template('forgot_password.html')

        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE email=? AND is_active=1', (email,)).fetchone()

        # Always show success message (security: don't reveal if email exists)
        if user:
            token      = secrets.token_urlsafe(48)
            expires    = time.time() + 3600  # 1 hour
            conn.execute('UPDATE users SET reset_token=?, reset_expires=? WHERE id=?',
                         (token, expires, user['id']))
            conn.commit()

            reset_url = url_for('reset_password', token=token, _external=True)
            sent = send_reset_email(email, user['username'], reset_url)
            audit('PASSWORD_RESET_REQUESTED', email)

            if not sent:
                # Email not configured — show link on screen for dev/testing
                flash(f'Email not configured. Reset link (dev only): {reset_url}', 'error')
                conn.close()
                return render_template('forgot_password.html')

        conn.close()
        flash('If that email exists in our system, a password reset link has been sent. Check your inbox.', 'success')
        return redirect(url_for('login'))

    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if 'user_id' in session:
        return redirect(url_for('index'))

    conn = get_db()
    user = conn.execute(
        'SELECT * FROM users WHERE reset_token=? AND reset_expires>?',
        (token, time.time())
    ).fetchone()

    if not user:
        conn.close()
        flash('This reset link is invalid or has expired. Please request a new one.', 'error')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        check_csrf()
        new_pwd = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        if len(new_pwd) < 8:
            flash('Password must be at least 8 characters.', 'error')
            conn.close()
            return render_template('reset_password.html', token=token)
        if new_pwd != confirm:
            flash('Passwords do not match.', 'error')
            conn.close()
            return render_template('reset_password.html', token=token)

        pwd_hash, salt = hash_password(new_pwd)
        conn.execute(
            'UPDATE users SET password_hash=?, salt=?, reset_token=NULL, reset_expires=NULL WHERE id=?',
            (pwd_hash, salt, user['id'])
        )
        conn.commit()
        conn.close()
        audit('PASSWORD_RESET_DONE', user['username'])
        flash('Password reset successfully! You can now log in with your new password.', 'success')
        return redirect(url_for('login'))

    conn.close()
    return render_template('reset_password.html', token=token)


def send_reset_email(to_email: str, username: str, reset_url: str) -> bool:
    """Send password reset link via Resend API."""
    api_key    = os.environ.get('RESEND_API_KEY', '').strip()
    email_from = os.environ.get('EMAIL_FROM', 'onboarding@resend.dev').strip()

    print(f"[RESET EMAIL] to={to_email} api_key_set={bool(api_key)}", flush=True)

    if not api_key:
        print("[RESET EMAIL] RESEND_API_KEY not set", flush=True)
        return False

    html_body = f"""
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:24px;background:#f5f6fa;border-radius:12px">
      <div style="background:#4f6ef7;border-radius:10px;padding:20px 24px;text-align:center;margin-bottom:20px">
        <div style="font-size:32px">&#9877;</div>
        <div style="color:#fff;font-size:18px;font-weight:700;margin-top:6px">LMRL Password Reset</div>
      </div>
      <div style="background:#fff;border-radius:10px;padding:24px;border:1px solid #e2e5f0">
        <p style="color:#1a1d2e;font-size:15px;margin-bottom:16px">Hi <strong>{username}</strong>,</p>
        <p style="color:#4a5068;font-size:14px;margin-bottom:20px">
          We received a request to reset your LMRL password. Click the button below to set a new password.
        </p>
        <div style="text-align:center;margin:24px 0">
          <a href="{reset_url}"
             style="background:#4f6ef7;color:#fff;padding:13px 28px;border-radius:8px;
                    text-decoration:none;font-weight:700;font-size:15px;display:inline-block">
            Reset My Password
          </a>
        </div>
        <p style="color:#8b91a7;font-size:13px">
          This link expires in <strong>1 hour</strong>. If you didn't request this, ignore this email — your password will not change.
        </p>
        <hr style="border:none;border-top:1px solid #e2e5f0;margin:16px 0">
        <p style="color:#8b91a7;font-size:11px;word-break:break-all">
          If the button doesn't work, copy this link: {reset_url}
        </p>
      </div>
    </div>
    """

    payload = json.dumps({
        "from":    email_from,
        "to":      [to_email],
        "subject": "Reset Your LMRL Password",
        "html":    html_body,
        "text":    f"Hi {username},\n\nReset your LMRL password here:\n{reset_url}\n\nExpires in 1 hour.",
    }).encode('utf-8')

    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data    = payload,
        method  = "POST",
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type":  "application/json",
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode()
            print(f"[RESET EMAIL] Resend {resp.status}: {body}", flush=True)
            return resp.status in (200, 201)
    except urllib.error.HTTPError as e:
        print(f"[RESET EMAIL] HTTP {e.code}: {e.read().decode()}", flush=True)
        return False
    except Exception as e:
        print(f"[RESET EMAIL] Error: {type(e).__name__}: {e}", flush=True)
        return False

# ═══════════════════════════════════════════════════════════════════════
#  DASHBOARD
# ═══════════════════════════════════════════════════════════════════════
@app.route('/')
@login_required
def index():
    # Viewers → redirect to their patient page immediately
    if session.get('role') == 'viewer':
        pid = session.get('viewer_pid')
        if pid:
            return redirect(url_for('patient_detail', pid=pid))
        flash('Your account is not linked to any patient. Contact an Admin.', 'error')
        return render_template('viewer_no_patient.html')

    conn = get_db()
    patients = conn.execute('SELECT * FROM patients ORDER BY created_at DESC').fetchall()
    stats = {
        'patients': conn.execute('SELECT COUNT(*) FROM patients').fetchone()[0],
        'records':  conn.execute('SELECT COUNT(*) FROM records').fetchone()[0],
        'rx':       conn.execute('SELECT COUNT(*) FROM prescriptions').fetchone()[0],
        'users':    conn.execute('SELECT COUNT(*) FROM users').fetchone()[0],
    }
    conn.close()
    return render_template('index.html', patients=patients, stats=stats)


# ═══════════════════════════════════════════════════════════════════════
#  SEARCH (blocked for viewers)
# ═══════════════════════════════════════════════════════════════════════
@app.route('/search')
@login_required
def search():
    if session.get('role') == 'viewer':
        flash('Search is disabled for viewer accounts.', 'error')
        pid = session.get('viewer_pid')
        return redirect(url_for('patient_detail', pid=pid) if pid else url_for('index'))

    q = request.args.get('q', '').strip()
    pts, recs = [], []
    if q:
        conn = get_db()
        pts = conn.execute(
            "SELECT * FROM patients WHERE name LIKE ? OR id LIKE ? OR phone LIKE ?",
            (f'%{q}%', f'%{q}%', f'%{q}%')).fetchall()
        recs = conn.execute(
            """SELECT r.*, p.name as pname FROM records r
               JOIN patients p ON r.patient_id=p.id
               WHERE r.diagnosis LIKE ? OR r.provider LIKE ? OR r.notes LIKE ?""",
            (f'%{q}%', f'%{q}%', f'%{q}%')).fetchall()
        conn.close()
    return render_template('search.html', q=q, patients=pts, records=recs)


# ═══════════════════════════════════════════════════════════════════════
#  PATIENTS
# ═══════════════════════════════════════════════════════════════════════
@app.route('/patient/add', methods=['GET', 'POST'])
@write_required
def add_patient():
    if request.method == 'POST':
        check_csrf()
        pid  = str(uuid.uuid4())
        name = request.form['name'].strip()
        dob  = request.form['dob']
        conn = get_db()
        conn.execute(
            'INSERT INTO patients (id,name,dob,gender,blood_group,phone,email,address,created_by) VALUES (?,?,?,?,?,?,?,?,?)',
            (pid, name, dob, request.form.get('gender'), request.form.get('blood_group'),
             request.form.get('phone'), request.form.get('email'),
             request.form.get('address'), session['user_id']))
        conn.execute(
            'INSERT INTO timelines (patient_id,event_date,event_type,title,description) VALUES (?,?,?,?,?)',
            (pid, dob, 'birth', 'Patient Registered', f'{name} registered in LMRL.'))
        conn.commit()
        conn.close()
        audit('ADD_PATIENT', name)
        flash(f'Patient "{name}" added. UID: {pid}', 'success')
        return redirect(url_for('patient_detail', pid=pid))
    return render_template('add_patient.html', patient=None, edit=False)


@app.route('/patient/<pid>')
@login_required
def patient_detail(pid):
    # Viewer access control — only their own patient
    if session.get('role') == 'viewer':
        allowed = session.get('viewer_pid')
        if pid != allowed:
            audit('VIEWER_BLOCKED', pid)
            abort(403)

    conn = get_db()
    patient = conn.execute('SELECT * FROM patients WHERE id=?', (pid,)).fetchone()
    if not patient:
        flash('Patient not found.', 'error')
        return redirect(url_for('index'))
    records  = conn.execute('SELECT * FROM records WHERE patient_id=? ORDER BY visit_date DESC', (pid,)).fetchall()
    rxs      = conn.execute('SELECT * FROM prescriptions WHERE patient_id=? ORDER BY prescribed_on DESC', (pid,)).fetchall()
    timeline = conn.execute('SELECT * FROM timelines WHERE patient_id=? ORDER BY event_date ASC', (pid,)).fetchall()
    conn.close()
    audit('VIEW_PATIENT', pid)
    return render_template('patient_detail.html', patient=patient,
                           records=records, prescriptions=rxs, timeline=timeline)


@app.route('/patient/<pid>/edit', methods=['GET', 'POST'])
@write_required
def edit_patient(pid):
    conn = get_db()
    patient = conn.execute('SELECT * FROM patients WHERE id=?', (pid,)).fetchone()
    if not patient:
        flash('Patient not found.', 'error')
        return redirect(url_for('index'))
    if request.method == 'POST':
        check_csrf()
        conn.execute(
            'UPDATE patients SET name=?,dob=?,gender=?,blood_group=?,phone=?,email=?,address=? WHERE id=?',
            (request.form['name'], request.form['dob'], request.form.get('gender'),
             request.form.get('blood_group'), request.form.get('phone'),
             request.form.get('email'), request.form.get('address'), pid))
        conn.commit()
        conn.close()
        audit('EDIT_PATIENT', pid)
        flash('Patient updated.', 'success')
        return redirect(url_for('patient_detail', pid=pid))
    conn.close()
    return render_template('add_patient.html', patient=patient, edit=True)


# ═══════════════════════════════════════════════════════════════════════
#  RECORDS / PRESCRIPTIONS / TIMELINE
# ═══════════════════════════════════════════════════════════════════════
@app.route('/patient/<pid>/record/add', methods=['GET', 'POST'])
@write_required
def add_record(pid):
    conn = get_db()
    patient = conn.execute('SELECT * FROM patients WHERE id=?', (pid,)).fetchone()
    if not patient: abort(404)
    if request.method == 'POST':
        check_csrf()
        fpath = None
        if 'file' in request.files:
            f = request.files['file']
            if f and f.filename and allowed_file(f.filename):
                fname = f"{uuid.uuid4().hex}_{secure_filename(f.filename)}"
                f.save(os.path.join(app.config['UPLOAD_FOLDER'], fname))
                fpath = fname
        conn.execute(
            'INSERT INTO records (patient_id,visit_date,provider,diagnosis,notes,file_path,created_by) VALUES (?,?,?,?,?,?,?)',
            (pid, request.form['visit_date'], request.form.get('provider'),
             request.form.get('diagnosis'), request.form.get('notes'), fpath, session['user_id']))
        conn.execute(
            'INSERT INTO timelines (patient_id,event_date,event_type,title,description) VALUES (?,?,?,?,?)',
            (pid, request.form['visit_date'], 'record',
             f"Visit: {request.form.get('diagnosis','General')}",
             f"Provider: {request.form.get('provider','N/A')}"))
        conn.commit()
        conn.close()
        audit('ADD_RECORD', pid)
        flash('Medical record added.', 'success')
        return redirect(url_for('patient_detail', pid=pid))
    conn.close()
    return render_template('add_record.html', patient=patient)


@app.route('/patient/<pid>/prescription/add', methods=['GET', 'POST'])
@write_required
def add_prescription(pid):
    conn = get_db()
    patient = conn.execute('SELECT * FROM patients WHERE id=?', (pid,)).fetchone()
    if not patient: abort(404)
    records = conn.execute('SELECT * FROM records WHERE patient_id=? ORDER BY visit_date DESC', (pid,)).fetchall()
    if request.method == 'POST':
        check_csrf()
        conn.execute(
            'INSERT INTO prescriptions (patient_id,record_id,drug_name,dosage,frequency,duration,notes,prescribed_on,created_by) VALUES (?,?,?,?,?,?,?,?,?)',
            (pid, request.form.get('record_id') or None,
             request.form['drug_name'], request.form.get('dosage'),
             request.form.get('frequency'), request.form.get('duration'),
             request.form.get('notes'), request.form.get('prescribed_on'), session['user_id']))
        conn.commit()
        conn.close()
        audit('ADD_RX', pid)
        flash('Prescription added.', 'success')
        return redirect(url_for('patient_detail', pid=pid))
    conn.close()
    return render_template('add_prescription.html', patient=patient, records=records)


@app.route('/patient/<pid>/timeline/add', methods=['GET', 'POST'])
@write_required
def add_timeline(pid):
    conn = get_db()
    patient = conn.execute('SELECT * FROM patients WHERE id=?', (pid,)).fetchone()
    if not patient: abort(404)
    if request.method == 'POST':
        check_csrf()
        conn.execute(
            'INSERT INTO timelines (patient_id,event_date,event_type,title,description) VALUES (?,?,?,?,?)',
            (pid, request.form['event_date'], request.form.get('event_type'),
             request.form['title'], request.form.get('description')))
        conn.commit()
        conn.close()
        audit('ADD_TIMELINE', pid)
        flash('Timeline event added.', 'success')
        return redirect(url_for('patient_detail', pid=pid))
    conn.close()
    return render_template('add_timeline.html', patient=patient)


# ── UPLOADS ───────────────────────────────────────────────────────────────────
@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    filename = os.path.basename(filename)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# ─────────────────────────────────────────────────────────────────────────────
init_db()

if __name__ == '__main__':
    app.run(debug=False, port=5000)
