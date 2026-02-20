"""Chat system routes."""
import os
import time
import uuid
import threading
from datetime import datetime
from flask import Blueprint, jsonify, request, send_from_directory
from werkzeug.utils import secure_filename

from app.config import Config
from app.database import get_db, get_db_readonly
from app.security import sanitize_output

chat_bp = Blueprint('chat', __name__)

_heartbeat_lock = threading.Lock()
chat_online_heartbeats = {}


def _allowed_chat_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in Config.CHAT_ALLOWED_EXTENSIONS


@chat_bp.route('/api/chat/history', methods=['GET'])
def chat_history():
    room = request.args.get('room', 'general')
    limit = min(int(request.args.get('limit', 50)), 200)
    after_id = int(request.args.get('after_id', 0))
    with get_db_readonly() as conn:
        cursor = conn.cursor()
        if after_id > 0:
            cursor.execute("""
                SELECT id, sender, room, message, file_name, file_path, timestamp
                FROM chat_messages WHERE room=? AND id>? ORDER BY id ASC LIMIT ?
            """, (room, after_id, limit))
        else:
            cursor.execute("""
                SELECT id, sender, room, message, file_name, file_path, timestamp
                FROM chat_messages WHERE room=? ORDER BY id DESC LIMIT ?
            """, (room, limit))
        messages = [dict(r) for r in cursor.fetchall()]
        if after_id == 0:
            messages.reverse()
    # Sanitize messages to prevent XSS
    for msg in messages:
        msg['message'] = sanitize_output(msg.get('message', ''))
        msg['sender'] = sanitize_output(msg.get('sender', ''))
    return jsonify({'messages': messages})


@chat_bp.route('/api/chat/send', methods=['POST'])
def chat_send_message():
    try:
        data = request.json or {}
        sender = data.get('sender', '').strip()
        room = data.get('room', 'general').strip()
        message = data.get('message', '').strip()
        file_name = data.get('file_name', '')
        file_path_val = data.get('file_path', '')

        if not sender or (not message and not file_name):
            return jsonify({'status': 'error', 'error': 'Empty message'}), 400

        # Sanitize room name
        if not room or len(room) > 100:
            room = 'general'

        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO chat_messages (sender, room, message, file_name, file_path, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (sender, room, message, file_name, file_path_val, now))
        msg_id = cursor.lastrowid
        conn.commit()
        conn.close()

        return jsonify({
            'status': 'ok',
            'message': {
                'id': msg_id, 'sender': sanitize_output(sender), 'room': room,
                'message': sanitize_output(message), 'file_name': file_name,
                'file_path': file_path_val, 'timestamp': now
            }
        })
    except Exception as e:
        return jsonify({'status': 'error', 'error': 'Failed to send message'}), 500


@chat_bp.route('/api/chat/heartbeat', methods=['POST'])
def chat_heartbeat():
    data = request.json or {}
    username = data.get('username', '')
    with _heartbeat_lock:
        if username and username != 'unknown':
            chat_online_heartbeats[username] = time.time()
        now = time.time()
        offline = [u for u, t in chat_online_heartbeats.items() if now - t > 15]
        for u in offline:
            del chat_online_heartbeats[u]
        users = list(chat_online_heartbeats.keys())
    return jsonify({'users': users})


@chat_bp.route('/api/chat/poll', methods=['GET'])
def chat_poll():
    username = request.args.get('username', '')
    after_id = int(request.args.get('after_id', 0))
    with get_db_readonly() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, sender, room, message, file_name, file_path, timestamp
            FROM chat_messages WHERE id > ? AND (room='general' OR room LIKE ? OR room LIKE ?)
            ORDER BY id ASC LIMIT 50
        """, (after_id, f'dm_{username}_%', f'dm_%_{username}'))
        messages = [dict(r) for r in cursor.fetchall()]
    for msg in messages:
        msg['message'] = sanitize_output(msg.get('message', ''))
        msg['sender'] = sanitize_output(msg.get('sender', ''))
    return jsonify({'messages': messages})


@chat_bp.route('/api/chat/rooms', methods=['GET'])
def chat_rooms():
    username = request.args.get('username', '')
    with get_db_readonly() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT DISTINCT room FROM chat_messages
            WHERE room='general' OR room LIKE ? OR room LIKE ? ORDER BY room
        """, (f'{username}_%', f'%_{username}'))
        rooms = [row['room'] for row in cursor.fetchall()]
    if 'general' not in rooms:
        rooms.insert(0, 'general')
    return jsonify({'rooms': rooms})


@chat_bp.route('/api/chat/upload', methods=['POST'])
def chat_upload():
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'error': 'No file'}), 400
    f = request.files['file']
    if f.filename == '' or not _allowed_chat_file(f.filename):
        return jsonify({'status': 'error', 'error': 'Invalid file type'}), 400

    # Check file size
    f.seek(0, os.SEEK_END)
    size = f.tell()
    f.seek(0)
    if size > Config.CHAT_MAX_FILE_SIZE:
        return jsonify({'status': 'error', 'error': 'File too large (max 5MB)'}), 400

    ext = f.filename.rsplit('.', 1)[1].lower()
    unique_name = f"{uuid.uuid4().hex[:12]}.{ext}"
    save_path = os.path.join(Config.CHAT_UPLOAD_DIR, unique_name)
    f.save(save_path)
    return jsonify({'status': 'ok', 'file_name': secure_filename(f.filename), 'file_path': unique_name})


@chat_bp.route('/data/chat_files/<path:filename>')
def chat_file_serve(filename):
    # Prevent path traversal
    safe_name = secure_filename(filename)
    if safe_name != filename:
        return jsonify({'error': 'Invalid filename'}), 400
    return send_from_directory(Config.CHAT_UPLOAD_DIR, safe_name)


@chat_bp.route('/api/chat/online', methods=['GET'])
def chat_online():
    with _heartbeat_lock:
        now = time.time()
        offline = [u for u, t in chat_online_heartbeats.items() if now - t > 15]
        for u in offline:
            del chat_online_heartbeats[u]
        users = list(chat_online_heartbeats.keys())
    return jsonify({'users': users})
