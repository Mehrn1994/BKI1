"""
Security module - Authentication, session management, CSRF, rate limiting, password hashing.
Uses bcrypt for passwords, token-based sessions, CSRF protection.
"""
import os
import re
import time
import secrets
import hashlib
import threading
import functools
from datetime import datetime, timedelta
from html import escape as html_escape

from flask import request, jsonify, g

from app.config import Config
from app.database import get_db, get_db_readonly

_rate_lock = threading.Lock()
_login_attempts = {}  # {ip: [timestamps]}
_api_rate = {}  # {ip:endpoint: [timestamps]}
_rate_cleanup_time = 0

# Try bcrypt, fall back to hashlib
try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False
    print("Warning: bcrypt not available, using SHA256 with salt (install bcrypt for better security)")


def hash_password(password):
    """Hash a password using bcrypt (preferred) or salted SHA256."""
    if BCRYPT_AVAILABLE:
        return bcrypt.hashpw(password.encode('utf-8'),
                             bcrypt.gensalt(rounds=Config.BCRYPT_ROUNDS)).decode('utf-8')
    salted = f"{Config.SALT_KEY}:{password}:{Config.SALT_KEY}"
    return hashlib.sha256(salted.encode()).hexdigest()


def verify_password(stored_hash, password):
    """Verify password against stored hash. Supports bcrypt, salted SHA256, and legacy SHA256."""
    if not stored_hash or not password:
        return False

    # Try bcrypt first
    if BCRYPT_AVAILABLE and stored_hash.startswith('$2'):
        try:
            return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
        except Exception:
            pass

    # Try salted SHA256
    salted = f"{Config.SALT_KEY}:{password}:{Config.SALT_KEY}"
    if stored_hash == hashlib.sha256(salted.encode()).hexdigest():
        return True

    # Try legacy unsalted SHA256
    if stored_hash == hashlib.sha256(password.encode()).hexdigest():
        return True

    return False


def should_migrate_password(stored_hash):
    """Check if password hash should be migrated to bcrypt."""
    if not BCRYPT_AVAILABLE:
        return False
    return not stored_hash.startswith('$2')


def generate_session_token():
    """Generate a cryptographically secure session token."""
    return secrets.token_urlsafe(48)


def generate_csrf_token():
    """Generate a CSRF token for forms."""
    return secrets.token_hex(32)


def create_session(username, ip_address=None, user_agent=None):
    """Create a new session and return the token."""
    token = generate_session_token()
    now = datetime.now()
    expires = now + timedelta(hours=Config.SESSION_LIFETIME_HOURS)

    conn = get_db()
    # Clean expired sessions for this user
    conn.execute("DELETE FROM sessions WHERE username=? AND expires_at<?",
                 (username, now.strftime('%Y-%m-%d %H:%M:%S')))
    conn.execute("""
        INSERT INTO sessions (token, username, created_at, expires_at, ip_address, user_agent)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (token, username, now.strftime('%Y-%m-%d %H:%M:%S'),
          expires.strftime('%Y-%m-%d %H:%M:%S'), ip_address, user_agent))
    conn.commit()
    conn.close()
    return token


def validate_session(token):
    """Validate a session token and return username if valid."""
    if not token:
        return None
    with get_db_readonly() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT username, expires_at FROM sessions
            WHERE token=? AND expires_at>?
        """, (token, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        row = cursor.fetchone()
        if row:
            return row['username']
    return None


def destroy_session(token):
    """Destroy a session."""
    if not token:
        return
    conn = get_db()
    conn.execute("DELETE FROM sessions WHERE token=?", (token,))
    conn.commit()
    conn.close()


def destroy_all_sessions(username):
    """Destroy all sessions for a user."""
    conn = get_db()
    conn.execute("DELETE FROM sessions WHERE username=?", (username,))
    conn.commit()
    conn.close()


def get_session_token():
    """Extract session token from request (header or cookie or body)."""
    # Check Authorization header
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        return auth[7:]
    # Check X-Session-Token header
    token = request.headers.get('X-Session-Token', '')
    if token:
        return token
    # Check request body
    if request.is_json and request.json:
        return request.json.get('session_token', '')
    # Check query parameter
    return request.args.get('session_token', '')


def get_current_user():
    """Get the current authenticated user from the session, or from username field (backward compat)."""
    token = get_session_token()
    if token:
        username = validate_session(token)
        if username:
            return username

    # Backward compatibility: check username in request
    if request.is_json and request.json:
        username = request.json.get('username', '')
        if username in Config.ALLOWED_USERS:
            return username
    username = request.args.get('username', '')
    if username in Config.ALLOWED_USERS:
        return username

    return None


def get_user_role(username):
    """Get the role for a user."""
    if not username:
        return None
    for role_name, role_config in Config.ROLES.items():
        if username in role_config['users']:
            return role_name
    if username in Config.ALLOWED_USERS:
        return 'operator'
    return None


def has_permission(username, permission):
    """Check if user has a specific permission."""
    role = get_user_role(username)
    if not role:
        return False
    role_config = Config.ROLES.get(role, {})
    permissions = role_config.get('permissions', [])
    return '*' in permissions or permission in permissions


def require_auth(f):
    """Decorator requiring authentication."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        username = get_current_user()
        if not username:
            return jsonify({'error': 'Authentication required', 'message': 'لطفا وارد شوید'}), 401
        g.current_user = username
        g.user_role = get_user_role(username)
        return f(*args, **kwargs)
    return decorated


def require_admin(f):
    """Decorator requiring admin role."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        username = get_current_user()
        if not username:
            return jsonify({'error': 'Authentication required', 'message': 'لطفا وارد شوید'}), 401
        if not has_permission(username, '*'):
            return jsonify({'error': 'Access denied', 'message': 'دسترسی فقط برای مدیر سیستم'}), 403
        g.current_user = username
        g.user_role = 'admin'
        return f(*args, **kwargs)
    return decorated


def require_permission(permission):
    """Decorator requiring a specific permission."""
    def decorator(f):
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            username = get_current_user()
            if not username:
                return jsonify({'error': 'Authentication required'}), 401
            if not has_permission(username, permission):
                return jsonify({'error': 'Insufficient permissions'}), 403
            g.current_user = username
            g.user_role = get_user_role(username)
            return f(*args, **kwargs)
        return decorated
    return decorator


def _cleanup_rate_limits():
    """Periodically clean up old rate limit entries to prevent memory leaks."""
    global _rate_cleanup_time
    now = time.time()
    if now - _rate_cleanup_time < 300:  # Cleanup every 5 minutes max
        return
    _rate_cleanup_time = now

    # Clean login attempts
    expired_ips = [ip for ip, times in _login_attempts.items()
                   if all(now - t > Config.LOGIN_WINDOW_SECONDS for t in times)]
    for ip in expired_ips:
        del _login_attempts[ip]

    # Clean API rate limits
    expired_keys = [k for k, times in _api_rate.items()
                    if all(now - t > Config.API_RATE_WINDOW for t in times)]
    for k in expired_keys:
        del _api_rate[k]


def is_rate_limited(ip):
    """Check if an IP has exceeded login attempt limit."""
    with _rate_lock:
        _cleanup_rate_limits()
        now = time.time()
        if ip not in _login_attempts:
            _login_attempts[ip] = []
        _login_attempts[ip] = [t for t in _login_attempts[ip] if now - t < Config.LOGIN_WINDOW_SECONDS]
        return len(_login_attempts[ip]) >= Config.LOGIN_MAX_ATTEMPTS


def record_login_attempt(ip):
    """Record a failed login attempt."""
    with _rate_lock:
        if ip not in _login_attempts:
            _login_attempts[ip] = []
        _login_attempts[ip].append(time.time())


def is_api_rate_limited(ip, endpoint):
    """Check if an IP has exceeded API rate limit for a specific endpoint."""
    with _rate_lock:
        key = f"{ip}:{endpoint}"
        now = time.time()
        if key not in _api_rate:
            _api_rate[key] = []
        _api_rate[key] = [t for t in _api_rate[key] if now - t < Config.API_RATE_WINDOW]
        if len(_api_rate[key]) >= Config.API_RATE_LIMIT:
            return True
        _api_rate[key].append(now)
        return False


def validate_octet(value):
    """Validate that value is a valid IP octet (0-255)."""
    try:
        n = int(value)
        return 0 <= n <= 255
    except (ValueError, TypeError):
        return False


def validate_ip(ip):
    """Validate IPv4 address format."""
    if not ip or not isinstance(ip, str):
        return False
    pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    match = re.match(pattern, ip)
    if not match:
        return False
    return all(0 <= int(g) <= 255 for g in match.groups())


def validate_host(host):
    """Validate hostname/IP for ping (prevent command injection)."""
    if not host or not isinstance(host, str):
        return False
    return bool(re.match(r'^[a-zA-Z0-9._:-]+$', host.strip()))


def sanitize_error(error):
    """Sanitize error message to prevent information leakage."""
    error_str = str(error)
    # Remove file paths
    error_str = re.sub(r'(/[a-zA-Z0-9_./\\-]+)', '[path]', error_str)
    # Remove SQL details
    error_str = re.sub(r'(table|column|index)\s+\w+', '[redacted]', error_str, flags=re.IGNORECASE)
    return error_str


def sanitize_output(text):
    """Sanitize text output to prevent XSS."""
    if not text:
        return ''
    return html_escape(str(text))


def validate_table_name(table_name):
    """Validate table name against whitelist to prevent SQL injection."""
    allowed = {
        'lan_ips', 'apn_mali', 'apn_ips', 'intranet_tunnels',
        'vpls_tunnels', 'tunnel_mali', 'tunnel200_ips', 'ptmp_connections',
        'reserved_ips', 'user_passwords', 'chat_messages'
    }
    return table_name in allowed
