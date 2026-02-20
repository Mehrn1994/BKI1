"""Tests for the Network Config Portal application."""
import os
import sys
import json
import tempfile
import pytest

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Override DB path before importing app
_test_db_fd, _test_db_path = tempfile.mkstemp(suffix='.db')
os.environ['BKI_DB_PATH'] = _test_db_path


from app import create_app
from app.config import Config
from app.security import (
    hash_password, verify_password, should_migrate_password,
    validate_octet, validate_ip, validate_host, validate_table_name,
    sanitize_output, sanitize_error, generate_session_token, generate_csrf_token
)


@pytest.fixture
def app():
    """Create app for testing."""
    Config.DB_PATH = _test_db_path
    application = create_app()
    application.config['TESTING'] = True
    yield application


@pytest.fixture
def client(app):
    """Test client."""
    return app.test_client()


# ==========================================
# Security Tests
# ==========================================
class TestPasswordHashing:
    def test_hash_and_verify(self):
        password = "TestPassword123"
        hashed = hash_password(password)
        assert hashed != password
        assert verify_password(hashed, password)

    def test_verify_wrong_password(self):
        hashed = hash_password("correct_password")
        assert not verify_password(hashed, "wrong_password")

    def test_verify_empty_inputs(self):
        assert not verify_password("", "password")
        assert not verify_password("hash", "")
        assert not verify_password("", "")
        assert not verify_password(None, "password")

    def test_should_migrate_sha256(self):
        import hashlib
        sha_hash = hashlib.sha256("test".encode()).hexdigest()
        # If bcrypt is available, SHA256 should be migrated
        try:
            import bcrypt
            assert should_migrate_password(sha_hash)
        except ImportError:
            assert not should_migrate_password(sha_hash)


class TestInputValidation:
    def test_validate_octet_valid(self):
        assert validate_octet(0)
        assert validate_octet(127)
        assert validate_octet(255)
        assert validate_octet("128")

    def test_validate_octet_invalid(self):
        assert not validate_octet(-1)
        assert not validate_octet(256)
        assert not validate_octet("abc")
        assert not validate_octet(None)

    def test_validate_ip_valid(self):
        assert validate_ip("10.0.0.1")
        assert validate_ip("192.168.1.1")
        assert validate_ip("255.255.255.255")
        assert validate_ip("0.0.0.0")

    def test_validate_ip_invalid(self):
        assert not validate_ip("")
        assert not validate_ip(None)
        assert not validate_ip("256.1.1.1")
        assert not validate_ip("10.0.0")
        assert not validate_ip("not.an.ip.addr")
        assert not validate_ip("10.0.0.1.2")
        assert not validate_ip("<script>alert(1)</script>")

    def test_validate_host(self):
        assert validate_host("10.0.0.1")
        assert validate_host("router1.bank.local")
        assert validate_host("192.168.1.1")

    def test_validate_host_injection(self):
        assert not validate_host("")
        assert not validate_host(None)
        assert not validate_host("10.0.0.1; rm -rf /")
        assert not validate_host("$(whoami)")
        assert not validate_host("host & cat /etc/passwd")

    def test_validate_table_name(self):
        assert validate_table_name("lan_ips")
        assert validate_table_name("apn_mali")
        assert validate_table_name("chat_messages")

    def test_validate_table_name_injection(self):
        assert not validate_table_name("'; DROP TABLE users; --")
        assert not validate_table_name("fake_table")
        assert not validate_table_name("")


class TestSanitization:
    def test_sanitize_output_xss(self):
        assert sanitize_output("<script>alert('xss')</script>") == "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"
        assert sanitize_output("<img onerror=alert(1)>") == "&lt;img onerror=alert(1)&gt;"

    def test_sanitize_output_safe(self):
        assert sanitize_output("normal text") == "normal text"
        assert sanitize_output("") == ""
        assert sanitize_output(None) == ""

    def test_sanitize_error_paths(self):
        result = sanitize_error("Error at /home/user/server.py line 42")
        assert "/home/user" not in result
        assert "[path]" in result

    def test_sanitize_error_sql(self):
        result = sanitize_error("no such table users")
        assert "table users" not in result.lower() or "[redacted]" in result


class TestTokenGeneration:
    def test_session_token_unique(self):
        t1 = generate_session_token()
        t2 = generate_session_token()
        assert t1 != t2
        assert len(t1) > 32

    def test_csrf_token_unique(self):
        t1 = generate_csrf_token()
        t2 = generate_csrf_token()
        assert t1 != t2
        assert len(t1) == 64  # 32 bytes hex


# ==========================================
# Config Tests
# ==========================================
class TestConfig:
    def test_allowed_users(self):
        assert "Sahebdel" in Config.ALLOWED_USERS
        assert Config.DB_ADMIN_USER == "Sahebdel"

    def test_roles(self):
        assert 'admin' in Config.ROLES
        assert 'operator' in Config.ROLES
        assert 'viewer' in Config.ROLES
        assert '*' in Config.ROLES['admin']['permissions']

    def test_security_defaults(self):
        assert Config.LOGIN_MAX_ATTEMPTS == 5
        assert Config.LOGIN_WINDOW_SECONDS == 300
        assert Config.BCRYPT_ROUNDS >= 10
        assert Config.SESSION_LIFETIME_HOURS >= 1


# ==========================================
# API Route Tests
# ==========================================
class TestAuthRoutes:
    def test_get_users(self, client):
        response = client.get('/api/users')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'users' in data
        assert len(data['users']) == len(Config.ALLOWED_USERS)

    def test_check_user_valid(self, client):
        response = client.post('/api/check-user',
                               data=json.dumps({'username': 'Sahebdel'}),
                               content_type='application/json')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['username'] == 'Sahebdel'

    def test_check_user_invalid(self, client):
        response = client.post('/api/check-user',
                               data=json.dumps({'username': 'hacker'}),
                               content_type='application/json')
        assert response.status_code == 403

    def test_register_short_password(self, client):
        response = client.post('/api/register',
                               data=json.dumps({'username': 'Sahebdel', 'password': '123'}),
                               content_type='application/json')
        assert response.status_code == 400

    def test_register_and_login(self, client):
        # Register
        response = client.post('/api/register',
                               data=json.dumps({'username': 'Sahebdel', 'password': 'TestPass123'}),
                               content_type='application/json')
        assert response.status_code == 200

        # Login
        response = client.post('/api/login',
                               data=json.dumps({'username': 'Sahebdel', 'password': 'TestPass123'}),
                               content_type='application/json')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] is True
        assert 'session_token' in data
        assert data['role'] == 'admin'

    def test_login_wrong_password(self, client):
        # Register first
        client.post('/api/register',
                    data=json.dumps({'username': 'Yarian', 'password': 'TestPass123'}),
                    content_type='application/json')
        # Wrong password
        response = client.post('/api/login',
                               data=json.dumps({'username': 'Yarian', 'password': 'WrongPass'}),
                               content_type='application/json')
        assert response.status_code == 401

    def test_login_unregistered(self, client):
        response = client.post('/api/login',
                               data=json.dumps({'username': 'Barari', 'password': 'test1234'}),
                               content_type='application/json')
        assert response.status_code == 401
        data = json.loads(response.data)
        assert data.get('need_register') is True

    def test_login_disallowed_user(self, client):
        response = client.post('/api/login',
                               data=json.dumps({'username': 'hacker', 'password': 'test1234'}),
                               content_type='application/json')
        assert response.status_code == 403


class TestSessionValidation:
    def test_validate_invalid_token(self, client):
        response = client.post('/api/session/validate',
                               data=json.dumps({'session_token': 'invalid-token'}),
                               content_type='application/json')
        assert response.status_code == 401

    def test_validate_valid_session(self, client):
        # Register + Login
        client.post('/api/register',
                    data=json.dumps({'username': 'Sahebdel', 'password': 'TestPass123'}),
                    content_type='application/json')
        login_resp = client.post('/api/login',
                                 data=json.dumps({'username': 'Sahebdel', 'password': 'TestPass123'}),
                                 content_type='application/json')
        token = json.loads(login_resp.data)['session_token']

        # Validate
        response = client.post('/api/session/validate',
                               data=json.dumps({'session_token': token}),
                               content_type='application/json')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['valid'] is True
        assert data['username'] == 'Sahebdel'


class TestStatsRoutes:
    def test_stats(self, client):
        response = client.get('/api/stats')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'total_ips' in data or 'error' not in data

    def test_health(self, client):
        response = client.get('/api/health')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'healthy'
        assert 'database' in data


class TestPageRoutes:
    def test_index(self, client):
        response = client.get('/')
        assert response.status_code == 200

    def test_login_page(self, client):
        response = client.get('/login')
        assert response.status_code == 200


class TestSecurityHeaders:
    def test_api_headers(self, client):
        response = client.get('/api/stats')
        assert response.headers.get('X-Content-Type-Options') == 'nosniff'
        assert response.headers.get('X-Frame-Options') == 'SAMEORIGIN'
        assert response.headers.get('X-XSS-Protection') == '1; mode=block'
        assert response.headers.get('Cache-Control') == 'no-store, max-age=0'

    def test_static_cache_headers(self, client):
        response = client.get('/static/css/design-system.css')
        if response.status_code == 200:
            assert 'max-age=3600' in response.headers.get('Cache-Control', '')


class TestErrorHandlers:
    def test_404_api(self, client):
        response = client.get('/api/nonexistent')
        assert response.status_code == 404
        data = json.loads(response.data)
        assert 'error' in data

    def test_404_page(self, client):
        response = client.get('/nonexistent-page')
        assert response.status_code == 404


# ==========================================
# Cleanup
# ==========================================
def teardown_module():
    """Cleanup test database."""
    try:
        os.close(_test_db_fd)
        os.unlink(_test_db_path)
    except Exception:
        pass
