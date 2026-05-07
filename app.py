"""
LMRL — Lifelong Medical Records Ledger
Roles:
  admin   — full access + admin panel + user management
  doctor  — add/edit patients, records, prescriptions, timelines
  nurse   — same as doctor
  viewer  — read-only access to all data (cannot add or edit anything)
Security:
  PBKDF2-SHA256 (260k iterations) · CSRF tokens · Login rate-limiting · Audit log
"""

from flask import (Flask, render_template, request, redirect, url_for,
                   flash, send_from_directory, session, abort)
import sqlite3, uuid, os, hashlib, hmac, secrets, time
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

_login_attempts: dict = {}
MAX_ATTEMPTS  = 5
LOCKOUT_SECS  = 15 * 60

# Roles that can WRITE data
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
            created_at    TEXT    DEFAULT CURRENT_TIMESTAMP,
            last_login    TEXT
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
    conn.commit()
    conn.close()

# ── SECURITY HELPERS ──────────────────────────────────────────────────────────
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
    """Doctor, Nurse, Admin can write. Viewer gets 403."""
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
    }

# ── ERROR HANDLERS ────────────────────────────────────────────────────────────
@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', code=403,
        msg="You don't have permission to access this page."), 403

@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', code=404,
        msg="The page you're looking for doesn't exist."), 404

# ── AUTH ──────────────────────────────────────────────────────────────────────
@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        check_csrf()
        username = request.form.get('username', '').strip()
        email    = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm_password', '')
        role     = request.form.get('role', 'viewer')
        if role not in ('doctor', 'nurse', 'viewer'):
            role = 'viewer'

        errs = []
        if not all([username, email, password]):
            errs.append('All fields are required.')
        if len(username) < 3:
            errs.append('Username must be at least 3 characters.')
        if len(password) < 8:
            errs.append('Password must be at least 8 characters.')
        if password != confirm:
            errs.append('Passwords do not match.')
        if errs:
            for e in errs: flash(e, 'error')
            return render_template('register.html')

        conn = get_db()
        if conn.execute('SELECT id FROM users WHERE username=? OR email=?',
                        (username, email)).fetchone():
            conn.close()
            flash('Username or email already taken.', 'error')
            return render_template('register.html')
        pwd_hash, salt = hash_password(password)
        conn.execute('INSERT INTO users (username,email,password_hash,salt,role) VALUES (?,?,?,?,?)',
                     (username, email, pwd_hash, salt, role))
        conn.commit()
        conn.close()
        audit('REGISTER', username)
        flash(f'Account created! Welcome, {username}. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


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

        if user and verify_password(password, user['password_hash'], user['salt']):
            clear_attempts(ip)
            session.permanent = False
            session['user_id']  = user['id']
            session['username'] = user['username']
            session['role']     = user['role']
            conn = get_db()
            conn.execute('UPDATE users SET last_login=? WHERE id=?',
                         (datetime.utcnow().isoformat(), user['id']))
            conn.commit()
            conn.close()
            audit('LOGIN', username)
            flash(f'Welcome back, {user["username"]}!', 'success')
            return redirect(url_for('index'))
        else:
            record_attempt(ip)
            left = max(0, MAX_ATTEMPTS - len(_login_attempts.get(ip, [])))
            audit('LOGIN_FAIL', username)
            flash(f'Invalid credentials. {left} attempts left.', 'error')
    return render_template('login.html')


@app.route('/logout')
def logout():
    audit('LOGOUT')
    session.clear()
    flash('You have been securely logged out.', 'success')
    return redirect(url_for('login'))


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
                conn.execute('UPDATE users SET password_hash=?,salt=? WHERE id=?',
                             (h, s, user['id']))
                conn.commit()
                audit('CHANGE_PASSWORD')
                flash('Password changed successfully.', 'success')
        conn.close()
        return redirect(url_for('profile'))
    conn = get_db()
    mp = conn.execute('SELECT COUNT(*) FROM patients WHERE created_by=?', (user['id'],)).fetchone()[0]
    mr = conn.execute('SELECT COUNT(*) FROM records  WHERE created_by=?', (user['id'],)).fetchone()[0]
    conn.close()
    return render_template('profile.html', user=user, my_patients=mp, my_records=mr)

# ── ADMIN ─────────────────────────────────────────────────────────────────────
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
        conn.execute('DELETE FROM users WHERE id=?', (uid,))
        conn.commit()
        audit('USER_DELETED', u['username'])
        flash(f'User "{u["username"]}" deleted.', 'success')
    conn.close()
    return redirect(url_for('admin_panel'))

# ── DOCTOR PANEL ──────────────────────────────────────────────────────────────
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
    audit('DOCTOR_VIEW')
    return render_template('doctor_panel.html', my_patients=my_patients,
                           recent_records=recent_records, recent_rx=recent_rx, stats=stats)

# ── DASHBOARD ─────────────────────────────────────────────────────────────────
@app.route('/')
@login_required
def index():
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

# ── SEARCH ────────────────────────────────────────────────────────────────────
@app.route('/search')
@login_required
def search():
    q = request.args.get('q', '').strip()
    pts, recs = [], []
    if q:
        conn = get_db()
        pts = conn.execute(
            "SELECT * FROM patients WHERE name LIKE ? OR id LIKE ? OR phone LIKE ?",
            (f'%{q}%', f'%{q}%', f'%{q}%')).fetchall()
        recs = conn.execute(
            """SELECT r.*, p.name as pname FROM records r JOIN patients p ON r.patient_id=p.id
               WHERE r.diagnosis LIKE ? OR r.provider LIKE ? OR r.notes LIKE ?""",
            (f'%{q}%', f'%{q}%', f'%{q}%')).fetchall()
        conn.close()
    return render_template('search.html', q=q, patients=pts, records=recs)

# ── PATIENTS ──────────────────────────────────────────────────────────────────
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
        flash(f'Patient "{name}" added successfully.', 'success')
        return redirect(url_for('patient_detail', pid=pid))
    return render_template('add_patient.html', patient=None, edit=False)


@app.route('/patient/<pid>')
@login_required
def patient_detail(pid):
    conn = get_db()
    patient = conn.execute('SELECT * FROM patients WHERE id=?', (pid,)).fetchone()
    if not patient:
        flash('Patient not found.', 'error')
        return redirect(url_for('index'))
    records = conn.execute('SELECT * FROM records WHERE patient_id=? ORDER BY visit_date DESC', (pid,)).fetchall()
    rxs     = conn.execute('SELECT * FROM prescriptions WHERE patient_id=? ORDER BY prescribed_on DESC', (pid,)).fetchall()
    timeline= conn.execute('SELECT * FROM timelines WHERE patient_id=? ORDER BY event_date ASC', (pid,)).fetchall()
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

# ── RECORDS ───────────────────────────────────────────────────────────────────
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

# ── PRESCRIPTIONS ─────────────────────────────────────────────────────────────
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

# ── TIMELINE ──────────────────────────────────────────────────────────────────
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
    filename = os.path.basename(filename)  # prevent path traversal
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ─────────────────────────────────────────────────────────────────────────────
init_db()

if __name__ == '__main__':
    app.run(debug=False, port=5000)
