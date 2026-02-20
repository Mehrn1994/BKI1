"""Authentication routes - Login, register, password management, sessions."""
from flask import Blueprint, jsonify, request

from app.config import Config
from app.database import get_db, get_db_readonly, log_audit
from app.security import (
    hash_password, verify_password, should_migrate_password,
    is_rate_limited, record_login_attempt,
    create_session, destroy_session, destroy_all_sessions,
    get_current_user, get_user_role, has_permission,
    require_auth, require_admin
)

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/api/users', methods=['GET'])
def get_users():
    with get_db_readonly() as conn:
        cursor = conn.cursor()
        users_info = []
        for username in Config.ALLOWED_USERS:
            cursor.execute("SELECT username, role FROM user_passwords WHERE username=?", (username,))
            row = cursor.fetchone()
            users_info.append({
                "name": username,
                "registered": row is not None,
                "role": row['role'] if row else None
            })
    return jsonify({"users": users_info})


@auth_bp.route('/api/check-user', methods=['POST'])
def check_user():
    data = request.json or {}
    username = data.get('username')
    if username not in Config.ALLOWED_USERS:
        return jsonify({"error": "Not allowed"}), 403
    with get_db_readonly() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM user_passwords WHERE username=?", (username,))
        has_password = cursor.fetchone() is not None
    return jsonify({"username": username, "has_password": has_password})


@auth_bp.route('/api/register', methods=['POST'])
def register_user():
    data = request.json or {}
    username = data.get('username')
    password = data.get('password')
    if username not in Config.ALLOWED_USERS:
        return jsonify({"error": "Not allowed"}), 403
    if not password or len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM user_passwords WHERE username=?", (username,))
    if cursor.fetchone():
        conn.close()
        return jsonify({"error": "Already registered"}), 400

    now_str = __import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    role = 'admin' if username == Config.DB_ADMIN_USER else 'operator'
    cursor.execute("INSERT INTO user_passwords VALUES (?, ?, ?, ?, ?)",
                   (username, hash_password(password), role, now_str, now_str))
    conn.commit()
    conn.close()

    log_audit('register', f'User {username} registered', username, 'auth',
              ip_address=request.remote_addr)
    return jsonify({"success": True})


@auth_bp.route('/api/change-password', methods=['POST'])
def change_password():
    data = request.json or {}
    username = data.get('username')
    old_password = data.get('old_password')
    new_password = data.get('new_password')

    if username not in Config.ALLOWED_USERS:
        return jsonify({"error": "Not allowed"}), 403
    if not new_password or len(new_password) < 8:
        return jsonify({"error": "New password must be at least 8 characters"}), 400

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM user_passwords WHERE username=?", (username,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "User not found"}), 404
    if not verify_password(row['password_hash'], old_password):
        conn.close()
        return jsonify({"error": "Current password is incorrect"}), 401

    cursor.execute("UPDATE user_passwords SET password_hash=? WHERE username=?",
                   (hash_password(new_password), username))
    conn.commit()
    conn.close()

    # Invalidate all sessions
    destroy_all_sessions(username)

    log_audit('change_password', f'Password changed for {username}', username, 'auth',
              ip_address=request.remote_addr)
    return jsonify({"success": True, "message": "Password changed successfully"})


@auth_bp.route('/api/login', methods=['POST'])
def login():
    client_ip = request.remote_addr
    if is_rate_limited(client_ip):
        return jsonify({"success": False, "message": "Too many attempts. Wait 5 minutes."}), 429

    data = request.json or {}
    username = data.get('username')
    password = data.get('password')

    if username not in Config.ALLOWED_USERS:
        record_login_attempt(client_ip)
        return jsonify({"success": False, "message": "Not allowed"}), 403

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM user_passwords WHERE username=?", (username,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        return jsonify({"success": False, "message": "Please register first", "need_register": True}), 401

    if not verify_password(row['password_hash'], password):
        record_login_attempt(client_ip)
        conn.close()
        log_audit('login_failed', f'Failed login for {username}', username, 'auth',
                  ip_address=client_ip)
        return jsonify({"success": False, "message": "Wrong password"}), 401

    # Migrate password to bcrypt if needed
    if should_migrate_password(row['password_hash']):
        cursor.execute("UPDATE user_passwords SET password_hash=? WHERE username=?",
                       (hash_password(password), username))

    cursor.execute("UPDATE user_passwords SET last_login=? WHERE username=?",
                   (__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S'), username))
    conn.commit()
    conn.close()

    # Create session
    token = create_session(username, ip_address=client_ip,
                           user_agent=request.headers.get('User-Agent', ''))

    role = get_user_role(username)
    log_audit('login', f'User {username} logged in', username, 'auth', ip_address=client_ip)

    return jsonify({
        "success": True,
        "session_token": token,
        "is_admin": role == 'admin',
        "role": role,
        "username": username
    })


@auth_bp.route('/api/logout', methods=['POST'])
def logout():
    data = request.json or {}
    token = data.get('session_token', '')
    if not token:
        token = request.headers.get('X-Session-Token', '')
    username = data.get('username', 'unknown')
    destroy_session(token)
    log_audit('logout', f'User {username} logged out', username, 'auth',
              ip_address=request.remote_addr)
    return jsonify({"success": True})


@auth_bp.route('/api/check-admin', methods=['GET'])
def check_admin():
    username = request.args.get('username', '')
    return jsonify({
        "is_admin": has_permission(username, '*'),
        "admin_user": Config.DB_ADMIN_USER,
        "role": get_user_role(username)
    })


@auth_bp.route('/api/session/validate', methods=['POST'])
def validate_session_route():
    data = request.json or {}
    token = data.get('session_token', '')
    from app.security import validate_session
    username = validate_session(token)
    if username:
        return jsonify({"valid": True, "username": username, "role": get_user_role(username)})
    return jsonify({"valid": False}), 401


@auth_bp.route('/api/sessions', methods=['GET'])
@require_auth
def list_sessions():
    """List active sessions for current user."""
    from flask import g
    with get_db_readonly() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT token, created_at, expires_at, ip_address, user_agent
            FROM sessions WHERE username=? AND expires_at>?
            ORDER BY created_at DESC
        """, (g.current_user, __import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        sessions = []
        for row in cursor.fetchall():
            sessions.append({
                'token_prefix': row['token'][:8] + '...',
                'created_at': row['created_at'],
                'expires_at': row['expires_at'],
                'ip_address': row['ip_address'],
                'user_agent': row['user_agent']
            })
    return jsonify({"sessions": sessions})


@auth_bp.route('/api/sessions/revoke-all', methods=['POST'])
@require_auth
def revoke_all_sessions():
    """Revoke all sessions for current user (logout everywhere)."""
    from flask import g
    destroy_all_sessions(g.current_user)
    log_audit('revoke_sessions', 'All sessions revoked', g.current_user, 'auth',
              ip_address=request.remote_addr)
    return jsonify({"success": True, "message": "All sessions revoked"})


@auth_bp.route('/api/password-recovery', methods=['POST'])
@require_admin
def admin_reset_password():
    """Admin can reset a user's password."""
    data = request.json or {}
    target_user = data.get('target_username', '')
    new_password = data.get('new_password', '')

    if target_user not in Config.ALLOWED_USERS:
        return jsonify({"error": "User not found"}), 404
    if not new_password or len(new_password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM user_passwords WHERE username=?", (target_user,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({"error": "User not registered"}), 404

    cursor.execute("UPDATE user_passwords SET password_hash=? WHERE username=?",
                   (hash_password(new_password), target_user))
    conn.commit()
    conn.close()

    destroy_all_sessions(target_user)

    from flask import g
    log_audit('password_reset', f'Password reset for {target_user} by admin',
              g.current_user, 'auth', ip_address=request.remote_addr)
    return jsonify({"success": True, "message": f"Password reset for {target_user}"})
