import os
import bcrypt
import uuid
import secrets
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, session, g, send_from_directory
from functools import wraps
import psycopg2
from psycopg2.extras import RealDictCursor
from urllib.parse import urlparse

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(16))
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Получаем DATABASE_URL из переменных окружения
DATABASE_URL = os.environ.get('DATABASE_URL')
USE_SQLITE = not DATABASE_URL  # Если нет DATABASE_URL, используем SQLite

if USE_SQLITE:
    # SQLite fallback
    import sqlite3
    print("⚠️ Используется SQLite (DATABASE_URL не задан)")
    
    def get_db():
        db = getattr(g, '_database', None)
        if db is None:
            db = g._database = sqlite3.connect('gallery.db')
            db.row_factory = sqlite3.Row
        return db
    
    @app.teardown_appcontext
    def close_connection(exception):
        db = getattr(g, '_database', None)
        if db is not None:
            db.close()
    
    def query(sql, params=None, commit=False):
        db = get_db()
        cursor = db.cursor()
        if params:
            cursor.execute(sql, params)
        else:
            cursor.execute(sql)
        if commit:
            db.commit()
        return cursor
    
    def query_one(sql, params=None):
        cur = query(sql, params)
        return cur.fetchone()
    
    def query_all(sql, params=None):
        cur = query(sql, params)
        return cur.fetchall()
    
else:
    # PostgreSQL
    print("✅ Используется PostgreSQL")
    
    def get_db():
        conn = getattr(g, '_database', None)
        if conn is None:
            conn = g._database = psycopg2.connect(DATABASE_URL)
            conn.autocommit = False
        return conn
    
    @app.teardown_appcontext
    def close_connection(exception):
        conn = getattr(g, '_database', None)
        if conn is not None:
            conn.close()
    
    def query(sql, params=None, commit=False):
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        try:
            if params:
                cur.execute(sql, params)
            else:
                cur.execute(sql)
            if commit:
                conn.commit()
            return cur
        except Exception as e:
            conn.rollback()
            raise e
    
    def query_one(sql, params=None):
        cur = query(sql, params)
        return cur.fetchone()
    
    def query_all(sql, params=None):
        cur = query(sql, params)
        return cur.fetchall()

# ---------------------- Инициализация БД ----------------------
def init_db():
    if USE_SQLITE:
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            verified INTEGER DEFAULT 0,
            shame INTEGER DEFAULT 0,
            banned_until TIMESTAMP,
            muted_until TIMESTAMP
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS uploads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            image_path TEXT NOT NULL,
            text TEXT,
            views INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS likes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            upload_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            value INTEGER NOT NULL,
            UNIQUE(upload_id, user_id),
            FOREIGN KEY (upload_id) REFERENCES uploads (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            upload_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            text TEXT NOT NULL,
            parent_id INTEGER DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (upload_id) REFERENCES uploads (id),
            FOREIGN KEY (parent_id) REFERENCES comments (id)
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            source_user_id INTEGER NOT NULL,
            source_username TEXT NOT NULL,
            upload_id INTEGER DEFAULT NULL,
            comment_id INTEGER DEFAULT NULL,
            read INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS upload_limits (
            user_id INTEGER PRIMARY KEY,
            upload_count INTEGER DEFAULT 0,
            last_reset TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS mod_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            moderator_id INTEGER NOT NULL,
            action_type TEXT NOT NULL,
            target_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (moderator_id) REFERENCES users (id)
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        )''')
        
        # Admin
        admin = cursor.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()
        if not admin:
            hashed = bcrypt.hashpw('admin555111'.encode('utf-8'), bcrypt.gensalt())
            cursor.execute("INSERT INTO users (username, password, role, verified) VALUES (?, ?, 'admin', 1)",
                           ('admin', hashed.decode('utf-8')))
        # Demo user
        demo = cursor.execute("SELECT id FROM users WHERE username = 'demo_user'").fetchone()
        if not demo:
            hashed = bcrypt.hashpw('demo123'.encode('utf-8'), bcrypt.gensalt())
            cursor.execute("INSERT INTO users (username, password, role, verified, shame) VALUES (?, ?, 'user', 0, 0)",
                           ('demo_user', hashed.decode('utf-8')))
        db.commit()
    else:
        # PostgreSQL
        conn = get_db()
        cur = conn.cursor()
        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                verified INTEGER DEFAULT 0,
                shame INTEGER DEFAULT 0,
                banned_until TIMESTAMP,
                muted_until TIMESTAMP
            )
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS uploads (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                username TEXT NOT NULL,
                image_path TEXT NOT NULL,
                text TEXT,
                views INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS likes (
                id SERIAL PRIMARY KEY,
                upload_id INTEGER NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                value INTEGER NOT NULL,
                UNIQUE(upload_id, user_id)
            )
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS comments (
                id SERIAL PRIMARY KEY,
                upload_id INTEGER NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                username TEXT NOT NULL,
                text TEXT NOT NULL,
                parent_id INTEGER DEFAULT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS notifications (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                type TEXT NOT NULL,
                source_user_id INTEGER NOT NULL,
                source_username TEXT NOT NULL,
                upload_id INTEGER DEFAULT NULL,
                comment_id INTEGER DEFAULT NULL,
                read INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS upload_limits (
                user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                upload_count INTEGER DEFAULT 0,
                last_reset TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS mod_actions (
                id SERIAL PRIMARY KEY,
                moderator_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                action_type TEXT NOT NULL,
                target_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS blacklist (
                id SERIAL PRIMARY KEY,
                name TEXT UNIQUE NOT NULL
            )
        ''')
        
        # Admin
        cur.execute("SELECT id FROM users WHERE username = 'admin'")
        if not cur.fetchone():
            hashed = bcrypt.hashpw('admin555111'.encode('utf-8'), bcrypt.gensalt())
            cur.execute("INSERT INTO users (username, password, role, verified) VALUES (%s, %s, 'admin', 1)",
                       ('admin', hashed.decode('utf-8')))
        # Demo user
        cur.execute("SELECT id FROM users WHERE username = 'demo_user'")
        if not cur.fetchone():
            hashed = bcrypt.hashpw('demo123'.encode('utf-8'), bcrypt.gensalt())
            cur.execute("INSERT INTO users (username, password, role, verified, shame) VALUES (%s, %s, 'user', 0, 0)",
                       ('demo_user', hashed.decode('utf-8')))
        conn.commit()

# Вызываем инициализацию
with app.app_context():
    init_db()

# ---------------------- Вспомогательные функции ----------------------
def get_user_role(user_id):
    user = query_one("SELECT role FROM users WHERE id = %s" if not USE_SQLITE else "SELECT role FROM users WHERE id = ?", (user_id,))
    return user['role'] if user else 'user'

def is_banned(user_id):
    user = query_one("SELECT banned_until FROM users WHERE id = %s" if not USE_SQLITE else "SELECT banned_until FROM users WHERE id = ?", (user_id,))
    if not user or not user['banned_until']:
        return False
    banned_until = datetime.fromisoformat(user['banned_until'].replace(' ', 'T') if isinstance(user['banned_until'], str) else user['banned_until'].isoformat())
    return datetime.now() < banned_until

def is_muted(user_id):
    user = query_one("SELECT muted_until FROM users WHERE id = %s" if not USE_SQLITE else "SELECT muted_until FROM users WHERE id = ?", (user_id,))
    if not user or not user['muted_until']:
        return False
    muted_until = datetime.fromisoformat(user['muted_until'].replace(' ', 'T') if isinstance(user['muted_until'], str) else user['muted_until'].isoformat())
    return datetime.now() < muted_until

def check_mod_limit(moderator_id):
    three_hours_ago = (datetime.now() - timedelta(hours=3)).isoformat()
    sql = "SELECT COUNT(*) as cnt FROM mod_actions WHERE moderator_id = %s AND created_at > %s" if not USE_SQLITE else "SELECT COUNT(*) as cnt FROM mod_actions WHERE moderator_id = ? AND created_at > ?"
    result = query_one(sql, (moderator_id, three_hours_ago))
    return result['cnt'] < 12

def log_mod_action(moderator_id, action_type, target_id=None):
    sql = "INSERT INTO mod_actions (moderator_id, action_type, target_id) VALUES (%s, %s, %s)" if not USE_SQLITE else "INSERT INTO mod_actions (moderator_id, action_type, target_id) VALUES (?, ?, ?)"
    query(sql, (moderator_id, action_type, target_id), commit=True)

def add_notification(user_id, type, source_user_id, source_username, upload_id=None, comment_id=None):
    sql = "INSERT INTO notifications (user_id, type, source_user_id, source_username, upload_id, comment_id) VALUES (%s, %s, %s, %s, %s, %s)" if not USE_SQLITE else "INSERT INTO notifications (user_id, type, source_user_id, source_username, upload_id, comment_id) VALUES (?, ?, ?, ?, ?, ?)"
    query(sql, (user_id, type, source_user_id, source_username, upload_id, comment_id), commit=True)

def check_upload_limit(user_id):
    sql = "SELECT upload_count, last_reset FROM upload_limits WHERE user_id = %s" if not USE_SQLITE else "SELECT upload_count, last_reset FROM upload_limits WHERE user_id = ?"
    row = query_one(sql, (user_id,))
    if not row:
        sql_insert = "INSERT INTO upload_limits (user_id, upload_count, last_reset) VALUES (%s, 0, %s)" if not USE_SQLITE else "INSERT INTO upload_limits (user_id, upload_count, last_reset) VALUES (?, 0, ?)"
        query(sql_insert, (user_id, datetime.now().isoformat()), commit=True)
        return True, 10, 0
    last_reset = datetime.fromisoformat(row['last_reset'].replace(' ', 'T') if isinstance(row['last_reset'], str) else row['last_reset'].isoformat())
    now = datetime.now()
    if now - last_reset > timedelta(minutes=3):
        sql_update = "UPDATE upload_limits SET upload_count = 0, last_reset = %s WHERE user_id = %s" if not USE_SQLITE else "UPDATE upload_limits SET upload_count = 0, last_reset = ? WHERE user_id = ?"
        query(sql_update, (now.isoformat(), user_id), commit=True)
        return True, 10, 0
    remaining = 10 - row['upload_count']
    if remaining > 0:
        return True, remaining, 0
    else:
        wait = int(180 - (now - last_reset).total_seconds())
        return False, 0, wait

def increment_upload_count(user_id):
    sql = "UPDATE upload_limits SET upload_count = upload_count + 1 WHERE user_id = %s" if not USE_SQLITE else "UPDATE upload_limits SET upload_count = upload_count + 1 WHERE user_id = ?"
    query(sql, (user_id,), commit=True)

def is_name_blacklisted(name):
    sql = "SELECT 1 FROM blacklist WHERE name = %s" if not USE_SQLITE else "SELECT 1 FROM blacklist WHERE name = ?"
    row = query_one(sql, (name,))
    return row is not None

# ---------------------- Декораторы ----------------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        role = get_user_role(session['user_id'])
        if role != 'admin':
            return jsonify({'error': 'Forbidden'}), 403
        return f(*args, **kwargs)
    return decorated

def moderator_or_admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        role = get_user_role(session['user_id'])
        if role not in ('admin', 'moderator'):
            return jsonify({'error': 'Forbidden'}), 403
        return f(*args, **kwargs)
    return decorated

# ---------------------- Routes ----------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ----- Auth -----
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'Missing fields'}), 400
    if is_name_blacklisted(username):
        return jsonify({'error': 'Это имя запрещено'}), 400
    sql = "SELECT id FROM users WHERE username = %s" if not USE_SQLITE else "SELECT id FROM users WHERE username = ?"
    existing = query_one(sql, (username,))
    if existing:
        return jsonify({'error': 'User exists'}), 400
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    sql_insert = "INSERT INTO users (username, password) VALUES (%s, %s)" if not USE_SQLITE else "INSERT INTO users (username, password) VALUES (?, ?)"
    query(sql_insert, (username, hashed.decode('utf-8')), commit=True)
    return jsonify({'message': 'Registered successfully'}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'Missing fields'}), 400
    sql = "SELECT id, username, password, role, verified, shame, banned_until, muted_until FROM users WHERE username = %s" if not USE_SQLITE else "SELECT id, username, password, role, verified, shame, banned_until, muted_until FROM users WHERE username = ?"
    user = query_one(sql, (username,))
    if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        return jsonify({'error': 'Invalid credentials'}), 401
    if user['banned_until']:
        banned_until = datetime.fromisoformat(user['banned_until'].replace(' ', 'T') if isinstance(user['banned_until'], str) else user['banned_until'].isoformat())
        if datetime.now() < banned_until:
            return jsonify({'error': f'Аккаунт забанен до {banned_until.strftime("%d.%m.%Y %H:%M")}'}), 403
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['role'] = user['role']
    session['verified'] = user['verified']
    session['shame'] = user['shame']
    return jsonify({
        'id': user['id'],
        'username': user['username'],
        'role': user['role'],
        'verified': user['verified'],
        'shame': user['shame'],
        'banned_until': user['banned_until'],
        'muted_until': user['muted_until']
    })

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out'})

@app.route('/api/me', methods=['GET'])
def me():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    sql = "SELECT id, username, role, verified, shame, banned_until, muted_until FROM users WHERE id = %s" if not USE_SQLITE else "SELECT id, username, role, verified, shame, banned_until, muted_until FROM users WHERE id = ?"
    user = query_one(sql, (session['user_id'],))
    return jsonify({
        'id': user['id'],
        'username': user['username'],
        'role': user['role'],
        'verified': user['verified'],
        'shame': user['shame'],
        'banned_until': user['banned_until'],
        'muted_until': user['muted_until']
    })

# ----- Uploads -----
@app.route('/api/uploads', methods=['GET'])
def get_uploads():
    if USE_SQLITE:
        uploads = query_all('''SELECT u.*,
            (SELECT COUNT(*) FROM likes WHERE upload_id = u.id AND value = 1) as likes,
            (SELECT COUNT(*) FROM likes WHERE upload_id = u.id AND value = -1) as dislikes,
            (SELECT verified FROM users WHERE id = u.user_id) as username_verified,
            (SELECT shame FROM users WHERE id = u.user_id) as username_shame
            FROM uploads u ORDER BY u.created_at DESC''')
    else:
        uploads = query_all('''SELECT u.*,
            (SELECT COUNT(*) FROM likes WHERE upload_id = u.id AND value = 1) as likes,
            (SELECT COUNT(*) FROM likes WHERE upload_id = u.id AND value = -1) as dislikes,
            (SELECT verified FROM users WHERE id = u.user_id) as username_verified,
            (SELECT shame FROM users WHERE id = u.user_id) as username_shame
            FROM uploads u ORDER BY u.created_at DESC''')
    return jsonify([dict(row) for row in uploads])

@app.route('/api/uploads', methods=['POST'])
@login_required
def create_upload():
    if is_banned(session['user_id']):
        return jsonify({'error': 'Ваш аккаунт забанен'}), 403

    allowed, remaining, wait = check_upload_limit(session['user_id'])
    if not allowed:
        return jsonify({'error': f'Лимит: вы загрузили 10 фото за 3 минуты. Подождите {wait} секунд'}), 429

    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400
    file = request.files['file']
    text = request.form.get('text', '')
    if file.filename == '':
        return jsonify({'error': 'Empty file'}), 400
    ext = file.filename.rsplit('.', 1)[-1].lower()
    if ext not in ('jpg', 'jpeg', 'png', 'webp', 'gif'):
        return jsonify({'error': 'Invalid format (jpg, jpeg, png, webp, gif)'}), 400
    if len(file.read()) > 3 * 1024 * 1024:
        return jsonify({'error': 'File too large (max 3MB)'}), 400
    file.seek(0)
    filename = f"{uuid.uuid4().hex}.{ext}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    sql = "INSERT INTO uploads (user_id, username, image_path, text) VALUES (%s, %s, %s, %s) RETURNING id" if not USE_SQLITE else "INSERT INTO uploads (user_id, username, image_path, text) VALUES (?, ?, ?, ?)"
    if USE_SQLITE:
        cur = query(sql, (session['user_id'], session['username'], filename, text), commit=True)
        upload_id = cur.lastrowid
    else:
        cur = query(sql, (session['user_id'], session['username'], filename, text), commit=True)
        upload_id = cur.fetchone()['id']
    increment_upload_count(session['user_id'])
    return jsonify({'id': upload_id, 'message': 'Uploaded'}), 201

@app.route('/api/uploads/<int:upload_id>', methods=['PUT'])
@login_required
def update_upload(upload_id):
    data = request.get_json()
    new_text = data.get('text', '').strip()
    sql = "SELECT * FROM uploads WHERE id = %s" if not USE_SQLITE else "SELECT * FROM uploads WHERE id = ?"
    upload = query_one(sql, (upload_id,))
    if not upload:
        return jsonify({'error': 'Not found'}), 404
    role = get_user_role(session['user_id'])
    if not (role == 'admin' or upload['user_id'] == session['user_id']):
        return jsonify({'error': 'Forbidden'}), 403
    sql_update = "UPDATE uploads SET text = %s WHERE id = %s" if not USE_SQLITE else "UPDATE uploads SET text = ? WHERE id = ?"
    query(sql_update, (new_text, upload_id), commit=True)
    return jsonify({'message': 'Updated'})

@app.route('/api/uploads/<int:upload_id>', methods=['DELETE'])
@login_required
def delete_upload(upload_id):
    sql = "SELECT * FROM uploads WHERE id = %s" if not USE_SQLITE else "SELECT * FROM uploads WHERE id = ?"
    upload = query_one(sql, (upload_id,))
    if not upload:
        return jsonify({'error': 'Not found'}), 404
    role = get_user_role(session['user_id'])
    if role == 'admin':
        pass
    elif role == 'moderator':
        if not check_mod_limit(session['user_id']):
            return jsonify({'error': 'Превышен лимит действий модератора (12 за 3 часа)'}), 429
        log_mod_action(session['user_id'], 'delete_photo', upload_id)
    elif upload['user_id'] == session['user_id']:
        pass
    else:
        return jsonify({'error': 'Forbidden'}), 403
    try:
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], upload['image_path']))
    except:
        pass
    sql_del = "DELETE FROM uploads WHERE id = %s" if not USE_SQLITE else "DELETE FROM uploads WHERE id = ?"
    query(sql_del, (upload_id,), commit=True)
    sql_del_likes = "DELETE FROM likes WHERE upload_id = %s" if not USE_SQLITE else "DELETE FROM likes WHERE upload_id = ?"
    query(sql_del_likes, (upload_id,), commit=True)
    sql_del_comments = "DELETE FROM comments WHERE upload_id = %s" if not USE_SQLITE else "DELETE FROM comments WHERE upload_id = ?"
    query(sql_del_comments, (upload_id,), commit=True)
    sql_del_notif = "DELETE FROM notifications WHERE upload_id = %s" if not USE_SQLITE else "DELETE FROM notifications WHERE upload_id = ?"
    query(sql_del_notif, (upload_id,), commit=True)
    return jsonify({'message': 'Deleted'})

@app.route('/api/uploads/<int:upload_id>/view', methods=['POST'])
def increment_views(upload_id):
    sql = "UPDATE uploads SET views = views + 1 WHERE id = %s" if not USE_SQLITE else "UPDATE uploads SET views = views + 1 WHERE id = ?"
    query(sql, (upload_id,), commit=True)
    return jsonify({'message': 'OK'})

# ----- Likes -----
@app.route('/api/uploads/<int:upload_id>/like', methods=['POST'])
@login_required
def like_upload(upload_id):
    if is_muted(session['user_id']):
        return jsonify({'error': 'Вы заглушены и не можете ставить лайки'}), 403
    data = request.get_json()
    value = data.get('value')
    if value not in (1, -1, 0):
        return jsonify({'error': 'Invalid value'}), 400
    sql_existing = "SELECT * FROM likes WHERE upload_id = %s AND user_id = %s" if not USE_SQLITE else "SELECT * FROM likes WHERE upload_id = ? AND user_id = ?"
    existing = query_one(sql_existing, (upload_id, session['user_id']))
    if value == 0:
        if existing:
            sql_del = "DELETE FROM likes WHERE upload_id = %s AND user_id = %s" if not USE_SQLITE else "DELETE FROM likes WHERE upload_id = ? AND user_id = ?"
            query(sql_del, (upload_id, session['user_id']), commit=True)
    else:
        if existing:
            sql_update = "UPDATE likes SET value = %s WHERE upload_id = %s AND user_id = %s" if not USE_SQLITE else "UPDATE likes SET value = ? WHERE upload_id = ? AND user_id = ?"
            query(sql_update, (value, upload_id, session['user_id']), commit=True)
        else:
            sql_insert = "INSERT INTO likes (upload_id, user_id, value) VALUES (%s, %s, %s)" if not USE_SQLITE else "INSERT INTO likes (upload_id, user_id, value) VALUES (?, ?, ?)"
            query(sql_insert, (upload_id, session['user_id'], value), commit=True)
    sql_likes = "SELECT COUNT(*) as cnt FROM likes WHERE upload_id = %s AND value = 1" if not USE_SQLITE else "SELECT COUNT(*) as cnt FROM likes WHERE upload_id = ? AND value = 1"
    likes = query_one(sql_likes, (upload_id,))['cnt']
    sql_dislikes = "SELECT COUNT(*) as cnt FROM likes WHERE upload_id = %s AND value = -1" if not USE_SQLITE else "SELECT COUNT(*) as cnt FROM likes WHERE upload_id = ? AND value = -1"
    dislikes = query_one(sql_dislikes, (upload_id,))['cnt']
    sql_upload = "SELECT user_id FROM uploads WHERE id = %s" if not USE_SQLITE else "SELECT user_id FROM uploads WHERE id = ?"
    upload = query_one(sql_upload, (upload_id,))
    if upload and upload['user_id'] != session['user_id']:
        add_notification(upload['user_id'], 'like' if value == 1 else 'dislike',
                         session['user_id'], session['username'], upload_id)
    return jsonify({'likes': likes, 'dislikes': dislikes})

# ----- Comments -----
@app.route('/api/uploads/<int:upload_id>/comments', methods=['GET'])
def get_comments(upload_id):
    sql = "SELECT * FROM comments WHERE upload_id = %s ORDER BY created_at ASC" if not USE_SQLITE else "SELECT * FROM comments WHERE upload_id = ? ORDER BY created_at ASC"
    comments = query_all(sql, (upload_id,))
    return jsonify([dict(row) for row in comments])

@app.route('/api/uploads/<int:upload_id>/comments', methods=['POST'])
@login_required
def add_comment(upload_id):
    if is_muted(session['user_id']):
        return jsonify({'error': 'Вы заглушены и не можете писать комментарии'}), 403
    data = request.get_json()
    text = data.get('text', '').strip()
    parent_id = data.get('parent_id', None)
    if not text:
        return jsonify({'error': 'Empty comment'}), 400
    sql_insert = "INSERT INTO comments (upload_id, user_id, username, text, parent_id) VALUES (%s, %s, %s, %s, %s) RETURNING id" if not USE_SQLITE else "INSERT INTO comments (upload_id, user_id, username, text, parent_id) VALUES (?, ?, ?, ?, ?)"
    if USE_SQLITE:
        cur = query(sql_insert, (upload_id, session['user_id'], session['username'], text, parent_id), commit=True)
        comment_id = cur.lastrowid
    else:
        cur = query(sql_insert, (upload_id, session['user_id'], session['username'], text, parent_id), commit=True)
        comment_id = cur.fetchone()['id']
    sql_upload = "SELECT user_id FROM uploads WHERE id = %s" if not USE_SQLITE else "SELECT user_id FROM uploads WHERE id = ?"
    upload = query_one(sql_upload, (upload_id,))
    if upload and upload['user_id'] != session['user_id']:
        add_notification(upload['user_id'], 'comment', session['user_id'], session['username'], upload_id, comment_id)
    if parent_id:
        sql_parent = "SELECT user_id FROM comments WHERE id = %s" if not USE_SQLITE else "SELECT user_id FROM comments WHERE id = ?"
        parent = query_one(sql_parent, (parent_id,))
        if parent and parent['user_id'] != session['user_id']:
            add_notification(parent['user_id'], 'reply', session['user_id'], session['username'], upload_id, comment_id)
    sql_comment = "SELECT * FROM comments WHERE id = %s" if not USE_SQLITE else "SELECT * FROM comments WHERE id = ?"
    comment = query_one(sql_comment, (comment_id,))
    return jsonify(dict(comment)), 201

@app.route('/api/comments/<int:comment_id>', methods=['DELETE'])
@login_required
def delete_comment(comment_id):
    sql = "SELECT * FROM comments WHERE id = %s" if not USE_SQLITE else "SELECT * FROM comments WHERE id = ?"
    comment = query_one(sql, (comment_id,))
    if not comment:
        return jsonify({'error': 'Not found'}), 404
    role = get_user_role(session['user_id'])
    if role == 'admin':
        pass
    elif role == 'moderator':
        if not check_mod_limit(session['user_id']):
            return jsonify({'error': 'Превышен лимит действий модератора (12 за 3 часа)'}), 429
        log_mod_action(session['user_id'], 'delete_comment', comment_id)
    elif comment['user_id'] == session['user_id']:
        pass
    else:
        return jsonify({'error': 'Forbidden'}), 403
    sql_del = "DELETE FROM comments WHERE id = %s" if not USE_SQLITE else "DELETE FROM comments WHERE id = ?"
    query(sql_del, (comment_id,), commit=True)
    sql_del_notif = "DELETE FROM notifications WHERE comment_id = %s" if not USE_SQLITE else "DELETE FROM notifications WHERE comment_id = ?"
    query(sql_del_notif, (comment_id,), commit=True)
    return jsonify({'message': 'Deleted'})

# ----- Notifications -----
@app.route('/api/notifications', methods=['GET'])
@login_required
def get_notifications():
    sql = "SELECT * FROM notifications WHERE user_id = %s ORDER BY created_at DESC LIMIT 50" if not USE_SQLITE else "SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50"
    notifs = query_all(sql, (session['user_id'],))
    sql_update = "UPDATE notifications SET read = 1 WHERE user_id = %s AND read = 0" if not USE_SQLITE else "UPDATE notifications SET read = 1 WHERE user_id = ? AND read = 0"
    query(sql_update, (session['user_id'],), commit=True)
    return jsonify([dict(row) for row in notifs])

@app.route('/api/notifications/unread', methods=['GET'])
@login_required
def unread_count():
    sql = "SELECT COUNT(*) as cnt FROM notifications WHERE user_id = %s AND read = 0" if not USE_SQLITE else "SELECT COUNT(*) as cnt FROM notifications WHERE user_id = ? AND read = 0"
    cnt = query_one(sql, (session['user_id'],))['cnt']
    return jsonify({'count': cnt})

# ----- Admin / Moderation -----
@app.route('/api/admin/users', methods=['GET'])
@admin_required
def list_users():
    sql = "SELECT id, username, role, verified, shame, banned_until, muted_until FROM users" if not USE_SQLITE else "SELECT id, username, role, verified, shame, banned_until, muted_until FROM users"
    users = query_all(sql)
    return jsonify([dict(row) for row in users])

@app.route('/api/admin/users/<int:user_id>/role', methods=['POST'])
@admin_required
def set_user_role(user_id):
    data = request.get_json()
    new_role = data.get('role')
    if new_role not in ('admin', 'moderator', 'user'):
        return jsonify({'error': 'Invalid role'}), 400
    if user_id == session['user_id'] and new_role != 'admin':
        return jsonify({'error': 'Cannot demote yourself'}), 403
    sql = "UPDATE users SET role = %s WHERE id = %s" if not USE_SQLITE else "UPDATE users SET role = ? WHERE id = ?"
    query(sql, (new_role, user_id), commit=True)
    return jsonify({'message': 'Role updated'})

@app.route('/api/admin/users/<int:user_id>/ban', methods=['POST'])
@admin_required
def ban_user(user_id):
    data = request.get_json()
    duration_hours = data.get('hours', 24)
    banned_until = (datetime.now() + timedelta(hours=duration_hours)).isoformat()
    sql = "UPDATE users SET banned_until = %s WHERE id = %s" if not USE_SQLITE else "UPDATE users SET banned_until = ? WHERE id = ?"
    query(sql, (banned_until, user_id), commit=True)
    return jsonify({'banned_until': banned_until})

@app.route('/api/admin/users/<int:user_id>/mute', methods=['POST'])
@admin_required
def mute_user(user_id):
    data = request.get_json()
    duration_hours = data.get('hours', 24)
    muted_until = (datetime.now() + timedelta(hours=duration_hours)).isoformat()
    sql = "UPDATE users SET muted_until = %s WHERE id = %s" if not USE_SQLITE else "UPDATE users SET muted_until = ? WHERE id = ?"
    query(sql, (muted_until, user_id), commit=True)
    return jsonify({'muted_until': muted_until})

@app.route('/api/admin/users/<int:user_id>/unban', methods=['POST'])
@admin_required
def unban_user(user_id):
    sql = "UPDATE users SET banned_until = NULL WHERE id = %s" if not USE_SQLITE else "UPDATE users SET banned_until = NULL WHERE id = ?"
    query(sql, (user_id,), commit=True)
    return jsonify({'message': 'Unbanned'})

@app.route('/api/admin/users/<int:user_id>/unmute', methods=['POST'])
@admin_required
def unmute_user(user_id):
    sql = "UPDATE users SET muted_until = NULL WHERE id = %s" if not USE_SQLITE else "UPDATE users SET muted_until = NULL WHERE id = ?"
    query(sql, (user_id,), commit=True)
    return jsonify({'message': 'Unmuted'})

@app.route('/api/admin/users/<int:user_id>/verify', methods=['POST'])
@admin_required
def verify_user(user_id):
    sql = "SELECT verified FROM users WHERE id = %s" if not USE_SQLITE else "SELECT verified FROM users WHERE id = ?"
    user = query_one(sql, (user_id,))
    if not user:
        return jsonify({'error': 'Not found'}), 404
    new_status = 1 if not user['verified'] else 0
    sql_update = "UPDATE users SET verified = %s WHERE id = %s" if not USE_SQLITE else "UPDATE users SET verified = ? WHERE id = ?"
    query(sql_update, (new_status, user_id), commit=True)
    if user_id == session['user_id']:
        session['verified'] = new_status
    return jsonify({'verified': new_status})

@app.route('/api/admin/users/<int:user_id>/shame', methods=['POST'])
@admin_required
def toggle_shame(user_id):
    sql = "SELECT shame FROM users WHERE id = %s" if not USE_SQLITE else "SELECT shame FROM users WHERE id = ?"
    user = query_one(sql, (user_id,))
    if not user:
        return jsonify({'error': 'Not found'}), 404
    new_status = 1 if not user['shame'] else 0
    sql_update = "UPDATE users SET shame = %s WHERE id = %s" if not USE_SQLITE else "UPDATE users SET shame = ? WHERE id = ?"
    query(sql_update, (new_status, user_id), commit=True)
    if user_id == session['user_id']:
        session['shame'] = new_status
    return jsonify({'shame': new_status})

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    if user_id == session['user_id']:
        return jsonify({'error': 'Cannot delete yourself'}), 403
    sql_user = "SELECT * FROM users WHERE id = %s" if not USE_SQLITE else "SELECT * FROM users WHERE id = ?"
    user = query_one(sql_user, (user_id,))
    if not user:
        return jsonify({'error': 'Not found'}), 404
    sql_uploads = "SELECT image_path FROM uploads WHERE user_id = %s" if not USE_SQLITE else "SELECT image_path FROM uploads WHERE user_id = ?"
    uploads = query_all(sql_uploads, (user_id,))
    for up in uploads:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], up['image_path']))
        except:
            pass
    sql_del_uploads = "DELETE FROM uploads WHERE user_id = %s" if not USE_SQLITE else "DELETE FROM uploads WHERE user_id = ?"
    query(sql_del_uploads, (user_id,), commit=True)
    sql_del_likes = "DELETE FROM likes WHERE user_id = %s" if not USE_SQLITE else "DELETE FROM likes WHERE user_id = ?"
    query(sql_del_likes, (user_id,), commit=True)
    sql_del_comments = "DELETE FROM comments WHERE user_id = %s" if not USE_SQLITE else "DELETE FROM comments WHERE user_id = ?"
    query(sql_del_comments, (user_id,), commit=True)
    sql_del_notif = "DELETE FROM notifications WHERE user_id = %s" if not USE_SQLITE else "DELETE FROM notifications WHERE user_id = ?"
    query(sql_del_notif, (user_id,), commit=True)
    sql_del_user = "DELETE FROM users WHERE id = %s" if not USE_SQLITE else "DELETE FROM users WHERE id = ?"
    query(sql_del_user, (user_id,), commit=True)
    return jsonify({'message': 'User deleted'})

@app.route('/api/admin/blacklist', methods=['GET'])
@admin_required
def get_blacklist():
    sql = "SELECT name FROM blacklist" if not USE_SQLITE else "SELECT name FROM blacklist"
    names = query_all(sql)
    return jsonify([row['name'] for row in names])

@app.route('/api/admin/blacklist', methods=['POST'])
@admin_required
def add_blacklist():
    data = request.get_json()
    name = data.get('name', '').strip()
    if not name:
        return jsonify({'error': 'Empty name'}), 400
    try:
        sql = "INSERT INTO blacklist (name) VALUES (%s)" if not USE_SQLITE else "INSERT INTO blacklist (name) VALUES (?)"
        query(sql, (name,), commit=True)
    except Exception as e:
        return jsonify({'error': 'Name already in blacklist'}), 400
    return jsonify({'message': 'Added'})

@app.route('/api/admin/blacklist/<name>', methods=['DELETE'])
@admin_required
def remove_blacklist(name):
    sql = "DELETE FROM blacklist WHERE name = %s" if not USE_SQLITE else "DELETE FROM blacklist WHERE name = ?"
    query(sql, (name,), commit=True)
    return jsonify({'message': 'Removed'})

@app.route('/api/activities', methods=['GET'])
@login_required
def get_activities():
    sql = "SELECT * FROM notifications WHERE user_id = %s AND read = 0 ORDER BY created_at DESC LIMIT 10" if not USE_SQLITE else "SELECT * FROM notifications WHERE user_id = ? AND read = 0 ORDER BY created_at DESC LIMIT 10"
    notifs = query_all(sql, (session['user_id'],))
    return jsonify([dict(row) for row in notifs])

if __name__ == '__main__':
    app.run(debug=True)