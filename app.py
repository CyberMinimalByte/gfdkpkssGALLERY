import os
import sqlite3
import bcrypt
import uuid
import secrets
import time
from datetime import datetime
from flask import Flask, render_template, request, jsonify, session, g, send_from_directory
from functools import wraps

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(16))
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ---------------------- Database ----------------------
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

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            verified INTEGER DEFAULT 0
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
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (upload_id) REFERENCES uploads (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )''')
        # Admin
        admin = cursor.execute("SELECT * FROM users WHERE username = 'admin'").fetchone()
        if not admin:
            hashed = bcrypt.hashpw('admin555111'.encode('utf-8'), bcrypt.gensalt())
            cursor.execute("INSERT INTO users (username, password, is_admin, verified) VALUES (?, ?, 1, 1)",
                           ('admin', hashed))
        # Demo user
        demo = cursor.execute("SELECT * FROM users WHERE username = 'demo_user'").fetchone()
        if not demo:
            hashed = bcrypt.hashpw('demo123'.encode('utf-8'), bcrypt.gensalt())
            cursor.execute("INSERT INTO users (username, password, is_admin, verified) VALUES (?, ?, 0, 0)",
                           ('demo_user', hashed))
        db.commit()

init_db()

# ---------------------- Auth decorators ----------------------
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
        db = get_db()
        user = db.execute("SELECT is_admin FROM users WHERE id = ?", (session['user_id'],)).fetchone()
        if not user or not user['is_admin']:
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
    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if existing:
        return jsonify({'error': 'User exists'}), 400
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    db.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))
    db.commit()
    return jsonify({'message': 'Registered successfully'}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'Missing fields'}), 400
    db = get_db()
    user = db.execute("SELECT id, username, password, is_admin, verified FROM users WHERE username = ?", (username,)).fetchone()
    if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password']):
        return jsonify({'error': 'Invalid credentials'}), 401
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['is_admin'] = user['is_admin']
    session['verified'] = user['verified']
    return jsonify({
        'id': user['id'],
        'username': user['username'],
        'is_admin': user['is_admin'],
        'verified': user['verified']
    })

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out'})

@app.route('/api/me', methods=['GET'])
def me():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    return jsonify({
        'id': session['user_id'],
        'username': session['username'],
        'is_admin': session['is_admin'],
        'verified': session.get('verified', 0)
    })

# ----- Uploads -----
@app.route('/api/uploads', methods=['GET'])
def get_uploads():
    db = get_db()
    # Подтягиваем verified автора
    uploads = db.execute('''SELECT u.*,
            (SELECT COUNT(*) FROM likes WHERE upload_id = u.id AND value = 1) as likes,
            (SELECT COUNT(*) FROM likes WHERE upload_id = u.id AND value = -1) as dislikes,
            (SELECT verified FROM users WHERE id = u.user_id) as username_verified
            FROM uploads u ORDER BY u.created_at DESC''').fetchall()
    return jsonify([dict(row) for row in uploads])

@app.route('/api/uploads', methods=['POST'])
@login_required
def create_upload():
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400
    file = request.files['file']
    text = request.form.get('text', '')
    if file.filename == '':
        return jsonify({'error': 'Empty file'}), 400
    ext = file.filename.rsplit('.', 1)[-1].lower()
    if ext not in ('jpg', 'jpeg', 'png', 'webp'):
        return jsonify({'error': 'Invalid format (jpg, jpeg, png, webp)'}), 400
    if len(file.read()) > 3 * 1024 * 1024:
        return jsonify({'error': 'File too large (max 3MB)'}), 400
    file.seek(0)
    filename = f"{uuid.uuid4().hex}.{ext}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    db = get_db()
    cursor = db.execute('''INSERT INTO uploads (user_id, username, image_path, text)
                           VALUES (?, ?, ?, ?)''',
                        (session['user_id'], session['username'], filename, text))
    db.commit()
    return jsonify({'id': cursor.lastrowid, 'message': 'Uploaded'}), 201

@app.route('/api/uploads/<int:upload_id>', methods=['PUT'])
@login_required
def update_upload(upload_id):
    data = request.get_json()
    new_text = data.get('text', '').strip()
    db = get_db()
    upload = db.execute("SELECT * FROM uploads WHERE id = ?", (upload_id,)).fetchone()
    if not upload:
        return jsonify({'error': 'Not found'}), 404
    if not (session['is_admin'] or upload['user_id'] == session['user_id']):
        return jsonify({'error': 'Forbidden'}), 403
    db.execute("UPDATE uploads SET text = ? WHERE id = ?", (new_text, upload_id))
    db.commit()
    return jsonify({'message': 'Updated'})

@app.route('/api/uploads/<int:upload_id>', methods=['DELETE'])
@login_required
def delete_upload(upload_id):
    db = get_db()
    upload = db.execute("SELECT * FROM uploads WHERE id = ?", (upload_id,)).fetchone()
    if not upload:
        return jsonify({'error': 'Not found'}), 404
    if not (session['is_admin'] or upload['user_id'] == session['user_id']):
        return jsonify({'error': 'Forbidden'}), 403
    try:
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], upload['image_path']))
    except:
        pass
    db.execute("DELETE FROM uploads WHERE id = ?", (upload_id,))
    db.execute("DELETE FROM likes WHERE upload_id = ?", (upload_id,))
    db.execute("DELETE FROM comments WHERE upload_id = ?", (upload_id,))
    db.commit()
    return jsonify({'message': 'Deleted'})

@app.route('/api/uploads/<int:upload_id>/view', methods=['POST'])
def increment_views(upload_id):
    db = get_db()
    db.execute("UPDATE uploads SET views = views + 1 WHERE id = ?", (upload_id,))
    db.commit()
    return jsonify({'message': 'OK'})

# ----- Likes -----
@app.route('/api/uploads/<int:upload_id>/like', methods=['POST'])
@login_required
def like_upload(upload_id):
    data = request.get_json()
    value = data.get('value')
    if value not in (1, -1, 0):
        return jsonify({'error': 'Invalid value'}), 400
    db = get_db()
    existing = db.execute("SELECT * FROM likes WHERE upload_id = ? AND user_id = ?",
                          (upload_id, session['user_id'])).fetchone()
    if value == 0:
        if existing:
            db.execute("DELETE FROM likes WHERE upload_id = ? AND user_id = ?",
                       (upload_id, session['user_id']))
    else:
        if existing:
            db.execute("UPDATE likes SET value = ? WHERE upload_id = ? AND user_id = ?",
                       (value, upload_id, session['user_id']))
        else:
            db.execute("INSERT INTO likes (upload_id, user_id, value) VALUES (?, ?, ?)",
                       (upload_id, session['user_id'], value))
    db.commit()
    likes = db.execute("SELECT COUNT(*) as cnt FROM likes WHERE upload_id = ? AND value = 1",
                       (upload_id,)).fetchone()['cnt']
    dislikes = db.execute("SELECT COUNT(*) as cnt FROM likes WHERE upload_id = ? AND value = -1",
                          (upload_id,)).fetchone()['cnt']
    return jsonify({'likes': likes, 'dislikes': dislikes})

# ----- Comments -----
@app.route('/api/uploads/<int:upload_id>/comments', methods=['GET'])
def get_comments(upload_id):
    db = get_db()
    comments = db.execute('''SELECT * FROM comments WHERE upload_id = ? ORDER BY created_at DESC''',
                          (upload_id,)).fetchall()
    return jsonify([dict(row) for row in comments])

@app.route('/api/uploads/<int:upload_id>/comments', methods=['POST'])
@login_required
def add_comment(upload_id):
    data = request.get_json()
    text = data.get('text', '').strip()
    if not text:
        return jsonify({'error': 'Empty comment'}), 400
    db = get_db()
    db.execute('''INSERT INTO comments (upload_id, user_id, username, text)
                  VALUES (?, ?, ?, ?)''',
               (upload_id, session['user_id'], session['username'], text))
    db.commit()
    comment_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    comment = db.execute("SELECT * FROM comments WHERE id = ?", (comment_id,)).fetchone()
    return jsonify(dict(comment)), 201

@app.route('/api/comments/<int:comment_id>', methods=['DELETE'])
@login_required
def delete_comment(comment_id):
    db = get_db()
    comment = db.execute("SELECT * FROM comments WHERE id = ?", (comment_id,)).fetchone()
    if not comment:
        return jsonify({'error': 'Not found'}), 404
    if not (session['is_admin'] or comment['user_id'] == session['user_id']):
        return jsonify({'error': 'Forbidden'}), 403
    db.execute("DELETE FROM comments WHERE id = ?", (comment_id,))
    db.commit()
    return jsonify({'message': 'Deleted'})

# ----- Admin users & verification -----
@app.route('/api/admin/users', methods=['GET'])
@admin_required
def list_users():
    db = get_db()
    users = db.execute("SELECT id, username, is_admin, verified FROM users").fetchall()
    return jsonify([dict(row) for row in users])

@app.route('/api/admin/users/<int:user_id>/verify', methods=['POST'])
@admin_required
def verify_user(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return jsonify({'error': 'Not found'}), 404
    new_status = 1 if not user['verified'] else 0
    db.execute("UPDATE users SET verified = ? WHERE id = ?", (new_status, user_id))
    db.commit()
    # Обновляем сессию, если это текущий пользователь
    if user_id == session['user_id']:
        session['verified'] = new_status
    return jsonify({'verified': new_status})

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    if user_id == session['user_id']:
        return jsonify({'error': 'Cannot delete yourself'}), 403
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return jsonify({'error': 'Not found'}), 404
    uploads = db.execute("SELECT image_path FROM uploads WHERE user_id = ?", (user_id,)).fetchall()
    for up in uploads:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], up['image_path']))
        except:
            pass
    db.execute("DELETE FROM uploads WHERE user_id = ?", (user_id,))
    db.execute("DELETE FROM likes WHERE user_id = ?", (user_id,))
    db.execute("DELETE FROM comments WHERE user_id = ?", (user_id,))
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    return jsonify({'message': 'User deleted'})

# ----- Polling для уведомлений -----
# Храним последнее время изменений (простое решение: возвращаем количество комментариев и лайков для каждого фото)
# Но для упрощения сделаем эндпоинт, который возвращает общее количество комментариев и лайков для всех фото,
# и клиент будет сравнивать с предыдущими значениями.
@app.route('/api/activities', methods=['GET'])
def get_activities():
    db = get_db()
    # Получаем последние 10 комментариев и лайков (с именами пользователей)
    # Для простоты: последние 5 комментариев и последние 5 лайков (с указанием фото)
    comments = db.execute('''SELECT c.id, c.upload_id, c.username, c.text, c.created_at, u.image_path
                             FROM comments c
                             JOIN uploads u ON c.upload_id = u.id
                             ORDER BY c.created_at DESC LIMIT 5''').fetchall()
    # Лайки не так важны, но можно тоже последние
    likes = db.execute('''SELECT l.upload_id, l.user_id, u.username, l.value, l.upload_id, u2.image_path
                          FROM likes l
                          JOIN users u ON l.user_id = u.id
                          JOIN uploads u2 ON l.upload_id = u2.id
                          ORDER BY l.rowid DESC LIMIT 5''').fetchall()
    return jsonify({
        'comments': [dict(row) for row in comments],
        'likes': [dict(row) for row in likes]
    })

if __name__ == '__main__':
    app.run(debug=True)