"""
Application Configuration
Centralized configuration with environment variable support.
"""
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Config:
    # Flask
    SECRET_KEY = os.environ.get('BKI_SECRET_KEY', os.urandom(32).hex())
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max upload

    # Database
    DB_PATH = os.environ.get('BKI_DB_PATH', os.path.join(BASE_DIR, 'data', 'network_ipam.db'))
    BACKUP_DIR = os.path.join(BASE_DIR, 'data', 'backups')
    CHAT_UPLOAD_DIR = os.path.join(BASE_DIR, 'data', 'chat_files')

    # Security
    SALT_KEY = os.environ.get('BKI_SALT_KEY', 'BKI-Network-Portal-2026')
    BCRYPT_ROUNDS = int(os.environ.get('BKI_BCRYPT_ROUNDS', '12'))
    SESSION_LIFETIME_HOURS = int(os.environ.get('BKI_SESSION_HOURS', '8'))

    # Rate limiting
    LOGIN_MAX_ATTEMPTS = 5
    LOGIN_WINDOW_SECONDS = 300
    API_RATE_LIMIT = 30
    API_RATE_WINDOW = 60

    # Auto-release
    AUTO_RELEASE_INTERVAL = 3600 * 6  # 6 hours
    RESERVATION_EXPIRY_DAYS = 60
    EXPIRY_WARNING_DAYS = [10, 5, 1]

    # Backup scheduler
    BACKUP_INTERVAL_HOURS = int(os.environ.get('BKI_BACKUP_HOURS', '24'))

    # Users & Roles
    ALLOWED_USERS = ["Yarian", "Sattari", "Barari", "Sahebdel", "Vahedi", "Aghajani", "Hossein", "Rezaei", "Bagheri"]
    DB_ADMIN_USER = "Sahebdel"

    # RBAC Roles
    ROLES = {
        'admin': {'users': ['Sahebdel'], 'permissions': ['*']},
        'operator': {'users': ['Yarian', 'Sattari', 'Barari', 'Vahedi', 'Aghajani', 'Hossein', 'Rezaei', 'Bagheri'],
                     'permissions': ['reserve', 'release', 'view', 'export', 'chat', 'config']},
        'viewer': {'users': [], 'permissions': ['view']},
    }

    # CORS
    CORS_ORIGINS = os.environ.get('BKI_CORS_ORIGINS', 'http://localhost:5000,http://127.0.0.1:5000').split(',')

    # Cache
    STATS_CACHE_SECONDS = 60

    # Chat
    CHAT_ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'xlsx', 'xls', 'doc', 'docx', 'txt', 'zip', 'rar', 'csv'}
    CHAT_MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB per chat file

    # Province tunnel templates
    PROVINCE_TUNNEL_TEMPLATES = {
        'ARD':   {'x': 23, 'vpls': {'hub': '10.23.251.1',  'subnet': '10.23.251'},  'mpls': {'hub': '10.23.251.1',  'subnet': '10.23.251'}},
        'AZGH':  {'x': 33, 'vpls': {'hub': '10.33.251.1',  'subnet': '10.33.251'},  'mpls': {'hub': '10.33.251.1',  'subnet': '10.33.251'}},
        'AZSH':  {'x': 3,  'vpls': {'hub': '10.3.251.1',   'subnet': '10.3.251'},   'mpls': {'hub': '10.3.251.1',   'subnet': '10.3.251'}},
        'BSH':   {'x': 18, 'vpls': {'hub': '10.18.251.2',  'subnet': '10.18.251'},  'mpls': {'hub': '10.18.251.2',  'subnet': '10.18.251'}},
        'CHB':   {'x': 16, 'vpls': {'hub': '10.16.251.1',  'subnet': '10.16.251'},  'mpls': {'hub': '10.16.251.1',  'subnet': '10.16.251'}},
        'ESF':   {'x': 10, 'vpls': {'hub': '10.10.251.1',  'subnet': '10.10.251'},  'mpls': {'hub': '10.10.251.1',  'subnet': '10.10.251'}},
        'FRS':   {'x': 7,  'vpls': {'hub': '10.7.251.2',   'subnet': '10.7.251'},   'mpls': {'hub': '10.7.252.1',   'subnet': '10.7.252'}},
        'GIL':   {'x': 21, 'vpls': {'hub': '10.21.251.1',  'subnet': '10.21.251'},  'mpls': {'hub': '10.21.251.1',  'subnet': '10.21.251'}},
        'GLS':   {'x': 22, 'vpls': {'hub': '10.22.251.1',  'subnet': '10.22.251'},  'mpls': {'hub': '10.22.251.1',  'subnet': '10.22.251'}},
        'HMD':   {'x': 15, 'vpls': {'hub': '10.15.251.1',  'subnet': '10.15.251'},  'mpls': {'hub': '10.15.251.1',  'subnet': '10.15.251'}},
        'HMZ':   {'x': 17, 'vpls': {'hub': '10.17.251.1',  'subnet': '10.17.251'},  'mpls': {'hub': '10.17.251.1',  'subnet': '10.17.251'}},
        'ILM':   {'x': 25, 'vpls': {'hub': '10.25.251.1',  'subnet': '10.25.251'},  'mpls': {'hub': '10.25.251.1',  'subnet': '10.25.251'}},
        'KHB':   {'x': 26, 'vpls': {'hub': '10.26.251.2',  'subnet': '10.26.251'},  'mpls': {'hub': '10.26.251.2',  'subnet': '10.26.251'}},
        'KHR':   {'x': 9,  'vpls': {'hub': '10.9.252.1',   'subnet': '10.9.252'},   'mpls': {'hub': '10.9.252.1',   'subnet': '10.9.252'}},
        'KHRJ':  {'x': 29, 'vpls': {'hub': '10.29.250.1',  'subnet': '10.29.250'},  'mpls': {'hub': '10.29.250.1',  'subnet': '10.29.250'}},
        'KHSH':  {'x': 30, 'vpls': {'hub': '10.30.251.1',  'subnet': '10.30.251'},  'mpls': {'hub': '10.30.251.1',  'subnet': '10.30.251'}},
        'KHZ':   {'x': 6,  'vpls': {'hub': '10.6.253.1',   'subnet': '10.6.253'},   'mpls': {'hub': '10.6.249.1',   'subnet': '10.6.249'}},
        'KRD':   {'x': 12, 'vpls': {'hub': '10.12.251.1',  'subnet': '10.12.251'},  'mpls': {'hub': '10.12.251.1',  'subnet': '10.12.251'}},
        'KRMSH': {'x': 5,  'vpls': {'hub': '10.5.251.1',   'subnet': '10.5.251'},   'mpls': {'hub': '10.5.251.1',   'subnet': '10.5.251'}},
        'LOR':   {'x': 14, 'vpls': {'hub': '10.14.251.1',  'subnet': '10.14.251'},  'mpls': {'hub': '10.14.251.1',  'subnet': '10.14.251'}},
        'MAZ':   {'x': 32, 'vpls': {'hub': '10.32.251.2',  'subnet': '10.32.251'},  'mpls': {'hub': '10.32.251.2',  'subnet': '10.32.251'}},
        'MRZ':   {'x': 24, 'vpls': {'hub': '10.24.251.1',  'subnet': '10.24.251'},  'mpls': {'hub': '10.24.251.1',  'subnet': '10.24.251'}},
        'QOM':   {'x': 28, 'vpls': {'hub': '10.28.251.1',  'subnet': '10.28.251'},  'mpls': {'hub': '10.28.251.1',  'subnet': '10.28.251'}},
        'QZV':   {'x': 27, 'vpls': {'hub': '10.27.251.1',  'subnet': '10.27.251'},  'mpls': {'hub': '10.27.251.1',  'subnet': '10.27.251'}},
        'SMN':   {'x': 13, 'vpls': {'hub': '10.13.251.1',  'subnet': '10.13.251'},  'mpls': {'hub': '10.13.240.1',  'subnet': '10.13.240'}},
        'SNB':   {'x': 11, 'vpls': {'hub': '10.11.251.1',  'subnet': '10.11.251'},  'mpls': {'hub': '10.11.251.1',  'subnet': '10.11.251'}},
        'YZD':   {'x': 20, 'vpls': {'hub': '10.20.251.1',  'subnet': '10.20.251'},  'mpls': {'hub': '10.20.251.1',  'subnet': '10.20.251'}},
    }

    # Server
    PORT = int(os.environ.get('BKI_PORT', '5000'))
    DEBUG = os.environ.get('BKI_DEBUG', 'false').lower() == 'true'
    BASE_DIR = BASE_DIR
