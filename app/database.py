"""
Database module - Connection management, schema init, audit trail.
Thread-safe connection pool with context manager support.
"""
import sqlite3
import os
import threading
from datetime import datetime
from contextlib import contextmanager

from app.config import Config

_local = threading.local()
_db_lock = threading.Lock()


def get_db():
    """Get a database connection (thread-local)."""
    conn = sqlite3.connect(Config.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def get_db_transaction():
    """Context manager for database transactions with automatic rollback on error."""
    conn = get_db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@contextmanager
def get_db_readonly():
    """Context manager for read-only database access."""
    conn = get_db()
    try:
        yield conn
    finally:
        conn.close()


def init_tables():
    """Initialize all database tables and indexes."""
    conn = get_db()
    cursor = conn.cursor()

    # User passwords
    cursor.execute("""CREATE TABLE IF NOT EXISTS user_passwords (
        username TEXT PRIMARY KEY, password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'operator',
        created_at TEXT, last_login TEXT)""")

    # Add role column if missing
    try:
        cursor.execute("ALTER TABLE user_passwords ADD COLUMN role TEXT DEFAULT 'operator'")
    except Exception:
        pass

    # Reserved IPs
    cursor.execute("""CREATE TABLE IF NOT EXISTS reserved_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT, province TEXT, octet2 INTEGER, octet3 INTEGER,
        branch_name TEXT, username TEXT, reservation_date TEXT, expiry_date TEXT,
        request_number TEXT, point_type TEXT, mehregostar_code TEXT,
        status TEXT DEFAULT 'reserved', activated_at TEXT, config_type TEXT)""")

    for col_def in [
        ("status", "TEXT DEFAULT 'reserved'"),
        ("activated_at", "TEXT"),
        ("config_type", "TEXT"),
    ]:
        try:
            cursor.execute(f"ALTER TABLE reserved_ips ADD COLUMN {col_def[0]} {col_def[1]}")
        except Exception:
            pass

    # PTMP connections
    cursor.execute("""CREATE TABLE IF NOT EXISTS ptmp_connections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        interface_name TEXT NOT NULL, description TEXT,
        branch_name TEXT, branch_name_en TEXT, bandwidth TEXT,
        ip_type TEXT, ip_address TEXT, ip_mask TEXT, encapsulation TEXT,
        province TEXT, province_abbr TEXT, router_hostname TEXT, router_file TEXT,
        status TEXT DEFAULT 'Used', username TEXT, reservation_date TEXT, lan_ip TEXT)""")

    # VPLS tunnels
    cursor.execute("""CREATE TABLE IF NOT EXISTS vpls_tunnels (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT, hub_ip TEXT, branch_ip TEXT,
        tunnel_name TEXT, description TEXT, province TEXT, branch_name TEXT,
        wan_ip TEXT, tunnel_dest TEXT,
        status TEXT DEFAULT 'Free', username TEXT, reservation_date TEXT)""")

    # Chat messages
    cursor.execute("""CREATE TABLE IF NOT EXISTS chat_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT NOT NULL, room TEXT NOT NULL DEFAULT 'general',
        message TEXT, file_name TEXT, file_path TEXT, timestamp TEXT NOT NULL)""")

    # Sessions table (new - for proper auth)
    cursor.execute("""CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY, username TEXT NOT NULL,
        created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
        ip_address TEXT, user_agent TEXT)""")

    # Audit trail (new - replaces JSON activity log)
    cursor.execute("""CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL, username TEXT NOT NULL DEFAULT 'System',
        action TEXT NOT NULL, category TEXT,
        target_table TEXT, target_id INTEGER,
        details TEXT, ip_address TEXT,
        old_values TEXT, new_values TEXT)""")

    # Notifications table (new)
    cursor.execute("""CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL, title TEXT NOT NULL,
        message TEXT, category TEXT DEFAULT 'info',
        is_read INTEGER DEFAULT 0,
        created_at TEXT NOT NULL, link TEXT)""")

    # Scheduled backups log (new)
    cursor.execute("""CREATE TABLE IF NOT EXISTS backup_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL, created_at TEXT NOT NULL,
        created_by TEXT DEFAULT 'System', size_bytes INTEGER,
        backup_type TEXT DEFAULT 'manual')""")

    # Create all indexes
    _create_indexes(cursor)

    conn.commit()
    conn.close()
    print("Database tables and indexes initialized")


def _create_indexes(cursor):
    """Create performance indexes."""
    indexes = [
        "CREATE INDEX IF NOT EXISTS idx_lan_ips_username ON lan_ips(username)",
        "CREATE INDEX IF NOT EXISTS idx_lan_ips_branch ON lan_ips(branch_name)",
        "CREATE INDEX IF NOT EXISTS idx_lan_ips_province ON lan_ips(province)",
        "CREATE INDEX IF NOT EXISTS idx_lan_ips_status ON lan_ips(status)",
        "CREATE INDEX IF NOT EXISTS idx_lan_ips_octet2 ON lan_ips(octet2)",
        "CREATE INDEX IF NOT EXISTS idx_lan_ips_octet2_octet3 ON lan_ips(octet2, octet3)",
        "CREATE INDEX IF NOT EXISTS idx_apn_ips_username ON apn_ips(username)",
        "CREATE INDEX IF NOT EXISTS idx_apn_ips_branch ON apn_ips(branch_name)",
        "CREATE INDEX IF NOT EXISTS idx_apn_mali_username ON apn_mali(username)",
        "CREATE INDEX IF NOT EXISTS idx_apn_mali_branch ON apn_mali(branch_name)",
        "CREATE INDEX IF NOT EXISTS idx_intranet_tunnels_status ON intranet_tunnels(status)",
        "CREATE INDEX IF NOT EXISTS idx_tunnel200_status ON tunnel200_ips(status)",
        "CREATE INDEX IF NOT EXISTS idx_tunnel200_branch ON tunnel200_ips(branch_name)",
        "CREATE INDEX IF NOT EXISTS idx_tunnel_mali_status ON tunnel_mali(status)",
        "CREATE INDEX IF NOT EXISTS idx_tunnel_mali_branch ON tunnel_mali(branch_name)",
        "CREATE INDEX IF NOT EXISTS idx_reserved_ips_expiry ON reserved_ips(expiry_date)",
        "CREATE INDEX IF NOT EXISTS idx_reserved_ips_status ON reserved_ips(status)",
        "CREATE INDEX IF NOT EXISTS idx_vpls_tunnels_province ON vpls_tunnels(province)",
        "CREATE INDEX IF NOT EXISTS idx_vpls_tunnels_branch ON vpls_tunnels(branch_name)",
        "CREATE INDEX IF NOT EXISTS idx_vpls_tunnels_status ON vpls_tunnels(status)",
        "CREATE INDEX IF NOT EXISTS idx_ptmp_branch ON ptmp_connections(branch_name)",
        "CREATE INDEX IF NOT EXISTS idx_ptmp_branch_en ON ptmp_connections(branch_name_en)",
        "CREATE INDEX IF NOT EXISTS idx_ptmp_province ON ptmp_connections(province)",
        "CREATE INDEX IF NOT EXISTS idx_ptmp_status ON ptmp_connections(status)",
        "CREATE INDEX IF NOT EXISTS idx_chat_room ON chat_messages(room)",
        "CREATE INDEX IF NOT EXISTS idx_chat_timestamp ON chat_messages(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_sessions_username ON sessions(username)",
        "CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)",
        "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_audit_username ON audit_log(username)",
        "CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action)",
        "CREATE INDEX IF NOT EXISTS idx_notifications_username ON notifications(username)",
        "CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications(is_read)",
    ]
    for idx in indexes:
        try:
            cursor.execute(idx)
        except Exception:
            pass


def log_audit(action, details="", username="System", category="info",
              target_table=None, target_id=None, ip_address=None,
              old_values=None, new_values=None):
    """Log an action to the audit trail (SQLite-based, thread-safe)."""
    try:
        with _db_lock:
            conn = get_db()
            conn.execute("""
                INSERT INTO audit_log (timestamp, username, action, category,
                    target_table, target_id, details, ip_address, old_values, new_values)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                username, action, category,
                target_table, target_id, details, ip_address,
                old_values, new_values
            ))
            conn.commit()
            conn.close()
    except Exception as e:
        print(f"Audit log error: {e}")


def create_notification(username, title, message="", category="info", link=None):
    """Create a notification for a user."""
    try:
        conn = get_db()
        conn.execute("""
            INSERT INTO notifications (username, title, message, category, created_at, link)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (username, title, message, category,
              datetime.now().strftime('%Y-%m-%d %H:%M:%S'), link))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Notification error: {e}")


def check_ip_conflict(octet2, octet3, exclude_id=None):
    """Check if an IP (octet2.octet3) is already in use across all tables."""
    conflicts = []
    with get_db_readonly() as conn:
        cursor = conn.cursor()

        # Check lan_ips
        if exclude_id:
            cursor.execute(
                "SELECT id, branch_name, status FROM lan_ips WHERE octet2=? AND octet3=? AND id!=? AND status!='Free'",
                (octet2, octet3, exclude_id))
        else:
            cursor.execute(
                "SELECT id, branch_name, status FROM lan_ips WHERE octet2=? AND octet3=? AND status!='Free'",
                (octet2, octet3))
        for row in cursor.fetchall():
            conflicts.append({
                'table': 'lan_ips', 'id': row['id'],
                'branch_name': row['branch_name'], 'status': row['status']
            })

        # Check reserved_ips
        cursor.execute(
            "SELECT id, branch_name, status FROM reserved_ips WHERE octet2=? AND octet3=? AND status='reserved'",
            (octet2, octet3))
        for row in cursor.fetchall():
            conflicts.append({
                'table': 'reserved_ips', 'id': row['id'],
                'branch_name': row['branch_name'], 'status': row['status']
            })

    return conflicts
