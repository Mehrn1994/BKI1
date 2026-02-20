"""Stats & dashboard routes."""
import time
from datetime import datetime, timedelta
from flask import Blueprint, jsonify, request

from app.database import get_db_readonly, log_audit

stats_bp = Blueprint('stats', __name__)

_stats_cache = {'data': None, 'time': 0}
STATS_CACHE_SECONDS = 60


@stats_bp.route('/api/stats', methods=['GET'])
def get_stats():
    global _stats_cache
    if _stats_cache['data'] and (time.time() - _stats_cache['time']) < STATS_CACHE_SECONDS:
        return jsonify(_stats_cache['data'])
    try:
        with get_db_readonly() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT
                    (SELECT COUNT(*) FROM lan_ips) as total_lan,
                    (SELECT COUNT(*) FROM lan_ips WHERE (username IS NULL OR username = '') AND (branch_name IS NULL OR branch_name = '')) as free_lan,
                    (SELECT COUNT(*) FROM intranet_tunnels) as total_tun,
                    (SELECT COUNT(*) FROM intranet_tunnels WHERE LOWER(status) = 'free') as free_tun,
                    (SELECT COUNT(*) FROM apn_ips) as total_apn,
                    (SELECT COUNT(*) FROM apn_ips WHERE username IS NULL OR username = '') as free_apn,
                    (SELECT COUNT(*) FROM apn_mali) as total_mali,
                    (SELECT COUNT(*) FROM apn_mali WHERE username IS NULL OR username = '') as free_mali,
                    (SELECT COUNT(*) FROM tunnel200_ips) as total_t200,
                    (SELECT COUNT(*) FROM tunnel200_ips WHERE status IS NULL OR status = '' OR LOWER(status) = 'free') as free_t200,
                    (SELECT COUNT(*) FROM tunnel_mali) as total_tmali,
                    (SELECT COUNT(*) FROM tunnel_mali WHERE status IS NULL OR status = '' OR LOWER(status) = 'free') as free_tmali,
                    (SELECT COUNT(*) FROM vpls_tunnels) as total_vpls,
                    (SELECT COUNT(*) FROM vpls_tunnels WHERE LOWER(status) = 'free') as free_vpls,
                    (SELECT COUNT(*) FROM ptmp_connections) as total_ptmp,
                    (SELECT COUNT(*) FROM ptmp_connections WHERE branch_name IS NOT NULL) as matched_ptmp
            """)
            row = cursor.fetchone()

        result = {
            'lan_ips': {'total': row[0], 'free': row[1], 'used': row[0] - row[1]},
            'tunnels': {'total': row[2], 'free': row[3], 'used': row[2] - row[3]},
            'apn': {'total': row[4], 'free': row[5], 'used': row[4] - row[5]},
            'apn_mali': {'total': row[6], 'free': row[7], 'used': row[6] - row[7]},
            'tunnel200': {'total': row[8], 'free': row[9], 'used': row[8] - row[9]},
            'tunnel_mali': {'total': row[10], 'free': row[11], 'used': row[10] - row[11]},
            'vpls': {'total': row[12], 'free': row[13], 'used': row[12] - row[13]},
            'ptmp': {'total': row[14], 'matched': row[15], 'used': row[14]}
        }
        _stats_cache['data'] = result
        _stats_cache['time'] = time.time()
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': 'Failed to load stats'}), 500


@stats_bp.route('/api/expiring-reservations', methods=['GET'])
def get_expiring_reservations():
    try:
        with get_db_readonly() as conn:
            cursor = conn.cursor()
            future_date = (datetime.now() + timedelta(days=7)).strftime('%Y-%m-%d')
            today = datetime.now().strftime('%Y-%m-%d')
            cursor.execute("""
                SELECT COUNT(*) FROM reserved_ips
                WHERE expiry_date BETWEEN ? AND ?
                AND (status = 'reserved' OR status IS NULL)
            """, (today, future_date))
            count = cursor.fetchone()[0]

            # Also get detailed list
            cursor.execute("""
                SELECT id, branch_name, province, octet2, octet3, expiry_date, username
                FROM reserved_ips
                WHERE expiry_date BETWEEN ? AND ?
                AND (status = 'reserved' OR status IS NULL)
                ORDER BY expiry_date ASC
            """, (today, future_date))
            items = []
            for row in cursor.fetchall():
                items.append({
                    'id': row['id'],
                    'branch_name': row['branch_name'] or '',
                    'province': row['province'] or '',
                    'ip': f"10.{row['octet2']}.{row['octet3']}.0/24",
                    'expiry_date': row['expiry_date'],
                    'username': row['username'] or '',
                    'days_remaining': max(0, (datetime.strptime(row['expiry_date'], '%Y-%m-%d') - datetime.now()).days)
                })
        return jsonify({'count': count, 'items': items})
    except Exception:
        return jsonify({'count': 0, 'items': []})


@stats_bp.route('/api/recent-reservations', methods=['GET'])
def get_recent_reservations():
    try:
        with get_db_readonly() as conn:
            cursor = conn.cursor()
            # Use UNION ALL for efficiency instead of N+1 queries
            cursor.execute("""
                SELECT branch_name, ip_wan_apn as ip, province, username, reservation_date, 'APN-INT' as type
                FROM apn_ips WHERE username IS NOT NULL AND username != ''
                UNION ALL
                SELECT branch_name, ip_wan as ip, province, username, reservation_date, 'APN-MALI' as type
                FROM apn_mali WHERE username IS NOT NULL AND username != ''
                UNION ALL
                SELECT branch_name, '10.' || octet2 || '.' || octet3 || '.0/24' as ip, province, username, reservation_date, 'LAN' as type
                FROM reserved_ips WHERE username IS NOT NULL AND username != ''
                UNION ALL
                SELECT COALESCE(branch_name, branch_name_en) as branch_name,
                       interface_name as ip, province, username, reservation_date, 'PTMP' as type
                FROM ptmp_connections WHERE username IS NOT NULL AND username != '' AND reservation_date IS NOT NULL
                ORDER BY reservation_date DESC LIMIT 10
            """)
            reservations = []
            for row in cursor.fetchall():
                reservations.append({
                    'branch_name': row[0] or '', 'ip': row[1] or '',
                    'province': row[2] or '', 'username': row[3] or '',
                    'date': row[4] or '', 'type': row[5]
                })
        return jsonify(reservations[:10])
    except Exception:
        return jsonify([])


@stats_bp.route('/api/top-provinces', methods=['GET'])
def get_top_provinces():
    try:
        with get_db_readonly() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT province, COUNT(*) as count FROM lan_ips
                WHERE province IS NOT NULL AND province != ''
                AND branch_name IS NOT NULL AND branch_name != ''
                GROUP BY province ORDER BY count DESC LIMIT 10
            """)
            provinces = [{'province': row['province'], 'count': row['count']} for row in cursor.fetchall()]
        return jsonify(provinces)
    except Exception:
        return jsonify([])


@stats_bp.route('/api/today-activity', methods=['GET'])
def get_today_activity():
    try:
        today = datetime.now().strftime('%Y-%m-%d')
        with get_db_readonly() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM audit_log WHERE timestamp LIKE ?", (f'{today}%',))
            count = cursor.fetchone()[0]
        return jsonify({'count': count})
    except Exception:
        return jsonify({'count': 0})


@stats_bp.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint for monitoring."""
    checks = {}
    try:
        with get_db_readonly() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM lan_ips")
            cursor.fetchone()
            checks['database'] = 'ok'
    except Exception as e:
        checks['database'] = f'error: {str(e)[:50]}'

    import os
    from app.config import Config
    checks['db_exists'] = os.path.exists(Config.DB_PATH)
    checks['backup_dir'] = os.path.exists(Config.BACKUP_DIR)
    checks['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    all_ok = all(v == 'ok' or v is True for v in checks.values() if isinstance(v, (str, bool)))
    return jsonify({'status': 'healthy' if all_ok else 'degraded', 'checks': checks})


@stats_bp.route('/api/notifications', methods=['GET'])
def get_notifications():
    """Get notifications for current user."""
    username = request.args.get('username', '')
    if not username:
        return jsonify([])
    try:
        with get_db_readonly() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, title, message, category, is_read, created_at, link
                FROM notifications WHERE username=?
                ORDER BY created_at DESC LIMIT 20
            """, (username,))
            notifs = []
            for row in cursor.fetchall():
                notifs.append({
                    'id': row['id'], 'title': row['title'],
                    'message': row['message'], 'category': row['category'],
                    'is_read': bool(row['is_read']), 'created_at': row['created_at'],
                    'link': row['link']
                })
        return jsonify(notifs)
    except Exception:
        return jsonify([])


@stats_bp.route('/api/notifications/read', methods=['POST'])
def mark_notification_read():
    data = request.json or {}
    notif_id = data.get('id')
    if notif_id:
        from app.database import get_db
        conn = get_db()
        conn.execute("UPDATE notifications SET is_read=1 WHERE id=?", (notif_id,))
        conn.commit()
        conn.close()
    return jsonify({'success': True})


@stats_bp.route('/api/notifications/read-all', methods=['POST'])
def mark_all_read():
    data = request.json or {}
    username = data.get('username', '')
    if username:
        from app.database import get_db
        conn = get_db()
        conn.execute("UPDATE notifications SET is_read=1 WHERE username=?", (username,))
        conn.commit()
        conn.close()
    return jsonify({'success': True})
