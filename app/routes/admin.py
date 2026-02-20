"""Admin routes - DB management, backup, import/export, audit log."""
import os
import shutil
from datetime import datetime
from flask import Blueprint, jsonify, request, Response

from app.config import Config
from app.database import get_db, get_db_readonly, log_audit
from app.security import (
    require_admin, validate_table_name, sanitize_error, sanitize_output
)

admin_bp = Blueprint('admin', __name__)


@admin_bp.route('/api/db/activity', methods=['GET'])
def get_activity():
    """Get audit log entries."""
    try:
        limit = min(int(request.args.get('limit', 100)), 500)
        with get_db_readonly() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, timestamp, username, action, category, details, ip_address
                FROM audit_log ORDER BY id DESC LIMIT ?
            """, (limit,))
            data = []
            for row in cursor.fetchall():
                data.append({
                    'type': row['category'] or 'info',
                    'title': row['action'],
                    'description': row['details'] or '',
                    'user': row['username'],
                    'time': row['timestamp'],
                    'ip': row['ip_address'] or ''
                })

        # Also check legacy JSON log for backward compat
        import json
        legacy_log = os.path.join(Config.BASE_DIR, 'data', 'activity.json')
        if os.path.exists(legacy_log) and not data:
            try:
                with open(legacy_log, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            except Exception:
                pass

        return jsonify(data)
    except Exception:
        return jsonify([])


@admin_bp.route('/api/audit-log', methods=['GET'])
def get_full_audit_log():
    """Get detailed audit log with filtering."""
    try:
        limit = min(int(request.args.get('limit', 100)), 500)
        username_filter = request.args.get('username', '').strip()
        action_filter = request.args.get('action', '').strip()
        date_from = request.args.get('date_from', '').strip()
        date_to = request.args.get('date_to', '').strip()

        query = "SELECT * FROM audit_log WHERE 1=1"
        params = []
        if username_filter:
            query += " AND username=?"
            params.append(username_filter)
        if action_filter:
            query += " AND action LIKE ?"
            params.append(f'%{action_filter}%')
        if date_from:
            query += " AND timestamp>=?"
            params.append(date_from)
        if date_to:
            query += " AND timestamp<=?"
            params.append(date_to + ' 23:59:59')
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with get_db_readonly() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            entries = [dict(row) for row in cursor.fetchall()]
        return jsonify(entries)
    except Exception:
        return jsonify([])


@admin_bp.route('/api/debug/tables', methods=['GET'])
def debug_tables():
    username = request.args.get('username', '')
    if username != Config.DB_ADMIN_USER:
        return jsonify({'error': 'Admin only'}), 403
    try:
        tables = {}
        # Whitelist of allowed tables - prevents SQL injection
        allowed = ['apn_ips', 'apn_mali', 'tunnel200_ips', 'tunnel_mali', 'lan_ips', 'intranet_tunnels']
        with get_db_readonly() as conn:
            cursor = conn.cursor()
            for table in allowed:
                try:
                    cursor.execute(f"SELECT COUNT(*) as count FROM {table}")
                    count = cursor.fetchone()[0]
                    cursor.execute(f"PRAGMA table_info({table})")
                    columns = [row[1] for row in cursor.fetchall()]
                    tables[table] = {'exists': True, 'count': count, 'columns': columns}
                except Exception:
                    tables[table] = {'exists': False}
        return jsonify(tables)
    except Exception:
        return jsonify({'error': 'Failed to load table info'}), 500


@admin_bp.route('/api/db/preview-excel', methods=['POST'])
def preview_excel():
    try:
        username = request.form.get('username', '')
        if username != Config.DB_ADMIN_USER:
            return jsonify({'error': 'Admin only'}), 403
        file = request.files.get('file')
        if not file:
            return jsonify({'error': 'No file selected'}), 400

        import pandas as pd
        if file.filename.endswith('.csv'):
            df = pd.read_csv(file)
        else:
            df = pd.read_excel(file)

        # Validate data before showing preview
        warnings = []
        if len(df) > 10000:
            warnings.append(f'Large file: {len(df)} rows')
        if df.isnull().sum().sum() > 0:
            null_cols = df.columns[df.isnull().any()].tolist()
            warnings.append(f'Null values in: {", ".join(null_cols[:5])}')

        return jsonify({
            'columns': list(df.columns),
            'preview': df.head(20).fillna('').to_dict('records'),
            'total_rows': len(df),
            'warnings': warnings
        })
    except Exception as e:
        return jsonify({'error': sanitize_error(e)}), 500


@admin_bp.route('/api/db/import-excel', methods=['POST'])
def import_excel():
    try:
        file = request.files.get('file')
        table_name = request.form.get('table')
        username = request.form.get('username')

        if username != Config.DB_ADMIN_USER:
            return jsonify({'error': 'Admin only'}), 403
        if not file or not table_name:
            return jsonify({'error': 'File and table name required'}), 400
        if not validate_table_name(table_name):
            return jsonify({'error': 'Invalid table name'}), 400

        import pandas as pd
        if file.filename.endswith('.csv'):
            df = pd.read_csv(file)
        else:
            df = pd.read_excel(file)

        # Data validation
        if len(df) == 0:
            return jsonify({'error': 'File is empty'}), 400
        if len(df) > 50000:
            return jsonify({'error': 'File too large (max 50000 rows)'}), 400

        # Auto-backup before import
        backup_name = f'backup_before_import_{datetime.now().strftime("%Y%m%d_%H%M%S")}.db'
        shutil.copy2(Config.DB_PATH, os.path.join(Config.BACKUP_DIR, backup_name))

        conn = get_db()
        df.to_sql(table_name, conn, if_exists='replace', index=False)
        conn.close()

        log_audit('import_excel', f'{table_name}: {len(df)} rows imported', username, 'admin',
                  target_table=table_name, ip_address=request.remote_addr)
        return jsonify({'success': True, 'rows': len(df), 'backup': backup_name})
    except Exception as e:
        return jsonify({'error': sanitize_error(e)}), 500


@admin_bp.route('/api/db/backup', methods=['POST'])
def create_backup():
    try:
        data = request.json or {}
        username = data.get('username', '')
        if username != Config.DB_ADMIN_USER:
            return jsonify({'error': 'Admin only'}), 403
        fname = f'backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.db'
        dest = os.path.join(Config.BACKUP_DIR, fname)
        shutil.copy2(Config.DB_PATH, dest)
        size = os.path.getsize(dest)

        # Log to backup_log table
        conn = get_db()
        conn.execute("INSERT INTO backup_log (filename, created_at, created_by, size_bytes, backup_type) VALUES (?,?,?,?,?)",
                     (fname, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), username, size, 'manual'))
        conn.commit()
        conn.close()

        log_audit('backup', fname, username, 'admin', ip_address=request.remote_addr)
        return jsonify({'success': True, 'filename': fname, 'size': f'{size/1024:.1f} KB'})
    except Exception as e:
        return jsonify({'error': sanitize_error(e)}), 500


@admin_bp.route('/api/db/backups', methods=['GET'])
def list_backups():
    try:
        backups = []
        if os.path.exists(Config.BACKUP_DIR):
            for f in sorted(os.listdir(Config.BACKUP_DIR), reverse=True):
                if f.endswith('.db'):
                    fpath = os.path.join(Config.BACKUP_DIR, f)
                    backups.append({
                        'filename': f,
                        'size': f'{os.path.getsize(fpath)/1024:.1f} KB',
                        'created': datetime.fromtimestamp(os.path.getmtime(fpath)).strftime('%Y-%m-%d %H:%M')
                    })
        return jsonify(backups)
    except Exception:
        return jsonify([])


@admin_bp.route('/api/db/restore', methods=['POST'])
def restore_backup():
    try:
        data = request.json or {}
        fname = data.get('filename')
        username = data.get('username')
        if username != Config.DB_ADMIN_USER:
            return jsonify({'error': 'Admin only'}), 403
        fname = os.path.basename(fname)
        if not fname.endswith('.db'):
            return jsonify({'error': 'Invalid file format'}), 400
        src = os.path.join(Config.BACKUP_DIR, fname)
        if os.path.exists(src):
            # Create safety backup before restore
            safety = f'backup_before_restore_{datetime.now().strftime("%Y%m%d_%H%M%S")}.db'
            shutil.copy2(Config.DB_PATH, os.path.join(Config.BACKUP_DIR, safety))
            shutil.copy2(src, Config.DB_PATH)
            log_audit('restore', f'Restored from {fname}', username, 'admin', ip_address=request.remote_addr)
            return jsonify({'success': True})
        return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        return jsonify({'error': sanitize_error(e)}), 500


@admin_bp.route('/api/db/reset-users', methods=['POST'])
def reset_users():
    try:
        data = request.json or {}
        username = data.get('username')
        if username != Config.DB_ADMIN_USER:
            return jsonify({'error': 'Admin only'}), 403
        conn = get_db()
        conn.execute('DELETE FROM user_passwords')
        conn.execute('DELETE FROM sessions')
        conn.commit()
        conn.close()
        log_audit('reset_users', 'All users and sessions reset', username, 'admin',
                  ip_address=request.remote_addr)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': sanitize_error(e)}), 500
