"""LAN IP management routes."""
from datetime import datetime, timedelta
from flask import Blueprint, jsonify, request

from app.config import Config
from app.database import get_db, get_db_readonly, get_db_transaction, log_audit, create_notification, check_ip_conflict
from app.security import (
    is_api_rate_limited, validate_octet, require_auth,
    get_current_user, sanitize_error
)

lan_bp = Blueprint('lan', __name__)


@lan_bp.route('/api/provinces', methods=['GET'])
def get_provinces():
    try:
        garbage = {'SW-Roof-To-Site', 'hgfvc', '???', 'رزرو', 'سیار', 'لوازم یدکی شاهان'}
        provinces = set()
        with get_db_readonly() as conn:
            cursor = conn.cursor()
            for table in ['lan_ips', 'apn_mali', 'apn_ips']:
                try:
                    cursor.execute(f"SELECT DISTINCT province FROM {table} WHERE province IS NOT NULL AND province != ''")
                    for row in cursor.fetchall():
                        if row[0] and len(row[0]) > 2 and row[0] not in garbage:
                            provinces.add(row[0])
                except Exception:
                    pass
        return jsonify(sorted(list(provinces)))
    except Exception:
        return jsonify([])


@lan_bp.route('/api/branches', methods=['GET'])
def get_branches():
    try:
        with get_db_readonly() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, branch_name, province, octet2, octet3, wan_ip
                FROM lan_ips WHERE branch_name IS NOT NULL AND branch_name != ''
                ORDER BY province, branch_name
            """)
            branches = []
            for row in cursor.fetchall():
                branches.append({
                    'name': row['branch_name'], 'province': row['province'] or '',
                    'lan_ip': f"10.{row['octet2']}.{row['octet3']}.0/24",
                    'x': row['octet2'], 'y': row['octet3'], 'type': 'active'
                })
            try:
                cursor.execute("""
                    SELECT id, branch_name, province, octet2, octet3
                    FROM reserved_ips WHERE status = 'reserved' OR status IS NULL
                """)
                for row in cursor.fetchall():
                    branches.append({
                        'name': f"{row['branch_name']} (reserved)",
                        'province': row['province'] or '',
                        'lan_ip': f"10.{row['octet2']}.{row['octet3']}.0/24",
                        'x': row['octet2'], 'y': row['octet3'], 'type': 'reserved'
                    })
            except Exception:
                pass
        return jsonify(branches)
    except Exception:
        return jsonify([])


@lan_bp.route('/api/mali-branches', methods=['GET'])
def get_mali_branches():
    return get_branches()


@lan_bp.route('/api/free-lan-ips', methods=['GET'])
def get_free_lan_ips():
    province = request.args.get('province')
    try:
        with get_db_readonly() as conn:
            cursor = conn.cursor()
            if province:
                cursor.execute("""
                    SELECT id, branch_name, province, octet2, octet3, wan_ip, status
                    FROM lan_ips
                    WHERE (branch_name IS NULL OR branch_name = '' OR status = 'Free')
                    AND (username IS NULL OR username = '') AND province = ?
                    ORDER BY octet2, octet3
                """, (province,))
            else:
                cursor.execute("""
                    SELECT id, branch_name, province, octet2, octet3, wan_ip, status
                    FROM lan_ips
                    WHERE (branch_name IS NULL OR branch_name = '' OR status = 'Free')
                    AND (username IS NULL OR username = '')
                    ORDER BY province, octet2, octet3 LIMIT 500
                """)
            ips = []
            for row in cursor.fetchall():
                ips.append({
                    'id': row['id'], 'ip': f"10.{row['octet2']}.{row['octet3']}.0/24",
                    'octet2': row['octet2'], 'octet3': row['octet3'],
                    'branch_name': row['branch_name'] or '', 'province': row['province'] or '',
                    'status': row['status'] or 'Free'
                })
        return jsonify(ips)
    except Exception:
        return jsonify([])


@lan_bp.route('/api/used-lan-ips', methods=['GET'])
def get_used_lan_ips():
    province = request.args.get('province')
    try:
        with get_db_readonly() as conn:
            cursor = conn.cursor()
            query = """
                SELECT id, branch_name, province, octet2, octet3, wan_ip, username, reservation_date, status
                FROM lan_ips WHERE branch_name IS NOT NULL AND branch_name != ''
            """
            params = []
            if province:
                query += " AND province = ?"
                params.append(province)
            query += " ORDER BY province, branch_name"
            cursor.execute(query, params)
            ips = []
            for row in cursor.fetchall():
                ips.append({
                    'id': row['id'], 'ip': f"10.{row['octet2']}.{row['octet3']}.0/24",
                    'octet2': row['octet2'], 'octet3': row['octet3'],
                    'branch_name': row['branch_name'] or '', 'province': row['province'] or '',
                    'username': row['username'] or '', 'reservation_date': row['reservation_date'] or '',
                    'status': row['status'] or 'Active'
                })
        return jsonify(ips)
    except Exception:
        return jsonify([])


@lan_bp.route('/api/lan-ips', methods=['GET'])
def get_lan_ips():
    try:
        page = request.args.get('page', type=int)
        per_page = min(request.args.get('per_page', 200, type=int), 500)
        province_filter = request.args.get('province', '').strip()

        with get_db_readonly() as conn:
            cursor = conn.cursor()
            query = """
                SELECT id, branch_name, province, octet2, octet3, wan_ip, status, username
                FROM lan_ips WHERE branch_name IS NOT NULL AND branch_name != ''
                AND octet2 IS NOT NULL AND octet3 IS NOT NULL
            """
            params = []
            if province_filter:
                query += " AND province = ?"
                params.append(province_filter)
            query += " ORDER BY province, branch_name"
            if page is not None:
                offset = (page - 1) * per_page
                query += " LIMIT ? OFFSET ?"
                params.extend([per_page, offset])
            cursor.execute(query, params)
            ips = []
            for row in cursor.fetchall():
                ips.append({
                    'id': row['id'], 'branch_name': row['branch_name'] or '',
                    'province': row['province'] or '', 'octet2': row['octet2'], 'octet3': row['octet3'],
                    'wan_ip': row['wan_ip'] or '', 'status': row['status'] or 'Active',
                    'username': row['username'] or ''
                })
        return jsonify({'success': True, 'data': ips})
    except Exception:
        return jsonify({'success': False, 'error': 'Failed to load data', 'data': []})


@lan_bp.route('/api/next-free-lan-ip', methods=['GET'])
def get_next_free_lan_ip():
    try:
        province = request.args.get('province', '').strip()
        if not province:
            return jsonify({'available': False, 'message': 'Province is required'})
        with get_db_readonly() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT DISTINCT octet2 FROM lan_ips WHERE province=? AND octet2 IS NOT NULL ORDER BY octet2", (province,))
            octet2_list = [row['octet2'] for row in cursor.fetchall()]
            if not octet2_list:
                return jsonify({'available': False, 'message': 'Province not found'})
            free_ips = []
            for o2 in octet2_list:
                cursor.execute("""
                    SELECT octet2, octet3 FROM lan_ips WHERE octet2=?
                    AND (username IS NULL OR username='') AND (branch_name IS NULL OR branch_name='')
                    AND (status IS NULL OR status='' OR LOWER(status)='free')
                    ORDER BY octet3 LIMIT 10
                """, (o2,))
                for row in cursor.fetchall():
                    free_ips.append({
                        'octet2': row['octet2'], 'octet3': row['octet3'],
                        'lan_ip': f"10.{row['octet2']}.{row['octet3']}.0/24", 'status': 'Free'
                    })
        if not free_ips:
            return jsonify({'available': False, 'message': 'No free IPs for this province'})
        return jsonify({
            'available': True, 'next_free': free_ips[0], 'free_list': free_ips[:10],
            'total_free': len(free_ips), 'province': province, 'octet2_values': octet2_list
        })
    except Exception as e:
        return jsonify({'available': False, 'message': sanitize_error(e)})


@lan_bp.route('/api/reserve-lan', methods=['POST'])
def reserve_lan_ip():
    try:
        if is_api_rate_limited(request.remote_addr, 'reserve-lan'):
            return jsonify({'status': 'error', 'message': 'Too many requests'}), 429
        data = request.json or {}
        lan_ip = data.get('lan_ip', '')
        province = data.get('province', '')
        branch_name = data.get('point_name_persian') or data.get('branch_name', '')
        username = data.get('reserved_by') or data.get('username', '')
        request_number = data.get('request_number', '')
        point_type = data.get('point_type', '')
        mehregostar_code = data.get('mehrgestar_code') or data.get('mehregostar_code', '')

        octet2 = data.get('octet2')
        octet3 = data.get('octet3')
        if lan_ip and not octet2:
            parts = lan_ip.replace('/24', '').split('.')
            if len(parts) >= 3:
                octet2 = int(parts[1])
                octet3 = int(parts[2])
        if not octet2 or not octet3 or not username:
            return jsonify({'status': 'error', 'message': 'Incomplete data'}), 400
        if not validate_octet(octet2) or not validate_octet(octet3):
            return jsonify({'status': 'error', 'message': 'Invalid IP format'}), 400

        # Check for IP conflicts
        conflicts = check_ip_conflict(octet2, octet3)
        if conflicts:
            return jsonify({'status': 'error', 'message': 'IP conflict detected', 'conflicts': conflicts}), 409

        now = datetime.now()
        expiry = now + timedelta(days=Config.RESERVATION_EXPIRY_DAYS)

        with get_db_transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT status FROM lan_ips WHERE octet2=? AND octet3=?", (octet2, octet3))
            row = cursor.fetchone()
            if row and row['status'] and row['status'].lower() in ('reserved', 'used', 'activated'):
                return jsonify({'status': 'error', 'message': 'IP already reserved'}), 409

            cursor.execute("""
                UPDATE lan_ips SET username=?, reservation_date=?, branch_name=?, status='Reserved'
                WHERE octet2=? AND octet3=?
            """, (username, now.strftime('%Y-%m-%d'), branch_name, octet2, octet3))

            cursor.execute("""
                INSERT INTO reserved_ips (province, octet2, octet3, branch_name, username,
                    reservation_date, expiry_date, request_number, point_type, mehregostar_code, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'reserved')
            """, (province, octet2, octet3, branch_name, username, now.strftime('%Y-%m-%d'),
                  expiry.strftime('%Y-%m-%d'), request_number, point_type, mehregostar_code))

        log_audit('reserve_lan', f'10.{octet2}.{octet3}.0/24 for {branch_name}', username,
                  'lan', 'lan_ips', ip_address=request.remote_addr)
        # Create expiry notification
        create_notification(username, 'IP Reserved',
                            f'10.{octet2}.{octet3}.0/24 reserved until {expiry.strftime("%Y-%m-%d")}',
                            'success', '/reserve-lan')

        return jsonify({
            'status': 'ok', 'success': True,
            'message': f'IP reserved: 10.{octet2}.{octet3}.0/24',
            'ip': f'10.{octet2}.{octet3}.0/24',
            'reservation_date': now.strftime('%Y-%m-%d'),
            'expiry_date': expiry.strftime('%Y-%m-%d')
        })
    except Exception as e:
        return jsonify({'status': 'error', 'success': False, 'message': sanitize_error(e)}), 500


@lan_bp.route('/api/release-lan', methods=['POST'])
def release_lan():
    try:
        data = request.json or {}
        lan_ip = data.get('lan_ip', '')
        parts = lan_ip.replace('/24', '').split('.')
        if len(parts) < 3:
            return jsonify({'status': 'error', 'message': 'Invalid IP'}), 400
        octet2, octet3 = int(parts[1]), int(parts[2])
        username = data.get('username', 'unknown')

        with get_db_transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE lan_ips SET username=NULL, reservation_date=NULL, status='Free' WHERE octet2=? AND octet3=?", (octet2, octet3))
            cursor.execute("DELETE FROM reserved_ips WHERE octet2=? AND octet3=?", (octet2, octet3))

        log_audit('release_lan', f'{lan_ip}', username, 'lan', ip_address=request.remote_addr)
        return jsonify({'status': 'ok', 'success': True, 'message': f'IP {lan_ip} released'})
    except Exception as e:
        return jsonify({'status': 'error', 'success': False, 'message': sanitize_error(e)})


@lan_bp.route('/api/release-used-lan', methods=['POST'])
def release_used_lan():
    try:
        data = request.json or {}
        octet2 = data.get('octet2')
        octet3 = data.get('octet3')
        lan_id = data.get('id')
        lan_ip = data.get('lan_ip')
        if lan_ip and not octet2:
            parts = lan_ip.replace('/24', '').split('.')
            if len(parts) >= 3:
                octet2, octet3 = int(parts[1]), int(parts[2])
        if not octet2 or not octet3:
            return jsonify({'status': 'error', 'message': 'Invalid IP'}), 400

        with get_db_transaction() as conn:
            cursor = conn.cursor()
            if lan_id:
                cursor.execute("UPDATE lan_ips SET username=NULL, reservation_date=NULL, branch_name=NULL, status='Free' WHERE id=?", (lan_id,))
            else:
                cursor.execute("UPDATE lan_ips SET username=NULL, reservation_date=NULL, branch_name=NULL, status='Free' WHERE octet2=? AND octet3=?", (octet2, octet3))
            cursor.execute("DELETE FROM reserved_ips WHERE octet2=? AND octet3=?", (octet2, octet3))

        log_audit('release_lan', f'10.{octet2}.{octet3}.0', data.get('username', 'unknown'), 'lan',
                  ip_address=request.remote_addr)
        return jsonify({'status': 'ok', 'success': True, 'message': f'IP 10.{octet2}.{octet3}.0 released'})
    except Exception as e:
        return jsonify({'status': 'error', 'success': False, 'message': sanitize_error(e)}), 500


@lan_bp.route('/api/release-reservation', methods=['POST'])
def release_reservation():
    try:
        data = request.json or {}
        rid = data.get('id')
        with get_db_transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT octet2, octet3 FROM reserved_ips WHERE id=?", (rid,))
            res = cursor.fetchone()
            if res:
                cursor.execute("UPDATE lan_ips SET username=NULL, reservation_date=NULL WHERE octet2=? AND octet3=?", (res['octet2'], res['octet3']))
                cursor.execute("DELETE FROM reserved_ips WHERE id=?", (rid,))
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': sanitize_error(e)}), 500


@lan_bp.route('/api/reserved-ips', methods=['GET'])
def get_reserved_ips():
    try:
        with get_db_readonly() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM reserved_ips ORDER BY reservation_date DESC")
            reserved = []
            for row in cursor.fetchall():
                reserved.append({
                    'id': row['id'], 'lan_ip': f"10.{row['octet2']}.{row['octet3']}.0/24",
                    'province': row['province'] or '', 'point_name_persian': row['branch_name'] or '',
                    'point_type': row['point_type'] or '', 'request_number': row['request_number'] or '',
                    'reserved_by': row['username'] or '', 'reserved_date': row['reservation_date'] or '',
                    'expiry_date': row['expiry_date'] or '', 'status': 'RESERVED',
                    'octet2': row['octet2'], 'octet3': row['octet3']
                })
        return jsonify(reserved)
    except Exception:
        return jsonify([])


@lan_bp.route('/api/activate-reservation', methods=['POST'])
def activate_reservation():
    try:
        data = request.json or {}
        lan_ip = data.get('lan_ip', '')
        config_type = data.get('config_type', 'unknown')
        username = data.get('username', '')
        parts = lan_ip.replace('/24', '').split('.')
        if len(parts) < 3:
            return jsonify({'status': 'ok', 'was_reserved': False})
        octet2, octet3 = int(parts[1]), int(parts[2])

        with get_db_transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, branch_name FROM reserved_ips
                WHERE octet2=? AND octet3=? AND (status='reserved' OR status IS NULL)
            """, (octet2, octet3))
            reservation = cursor.fetchone()
            if reservation:
                now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                cursor.execute("UPDATE reserved_ips SET status='activated', activated_at=?, config_type=? WHERE id=?",
                               (now, config_type, reservation['id']))
                cursor.execute("UPDATE lan_ips SET status='Used', username=? WHERE octet2=? AND octet3=?",
                               (username, octet2, octet3))
                log_audit('activate_reservation', f'10.{octet2}.{octet3}.0/24 - {reservation["branch_name"]}',
                          username, 'lan', ip_address=request.remote_addr)
                return jsonify({'status': 'ok', 'was_reserved': True, 'message': 'Reservation activated'})

        return jsonify({'status': 'ok', 'was_reserved': False})
    except Exception as e:
        return jsonify({'status': 'error', 'was_reserved': False, 'message': sanitize_error(e)})


@lan_bp.route('/api/check-request-number', methods=['GET'])
def check_request_number():
    rn = request.args.get('request_number')
    try:
        with get_db_readonly() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM reserved_ips WHERE request_number=?", (rn,))
            row = cursor.fetchone()
        return jsonify({'exists': row is not None, 'data': dict(row) if row else None})
    except Exception:
        return jsonify({'exists': False})


@lan_bp.route('/api/check-expired-reservations', methods=['GET', 'POST'])
def check_expired_reservations():
    try:
        today = datetime.now().strftime('%Y-%m-%d')
        with get_db_readonly() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, octet2, octet3, branch_name, username, reservation_date, expiry_date, status
                FROM reserved_ips WHERE expiry_date < ? AND (status='reserved' OR status IS NULL)
            """, (today,))
            expired = cursor.fetchall()

        expired_list = [{
            'id': row['id'], 'ip': f"10.{row['octet2']}.{row['octet3']}.0/24",
            'branch_name': row['branch_name'], 'username': row['username'],
            'reservation_date': row['reservation_date'], 'expiry_date': row['expiry_date'],
            'status': row['status']
        } for row in expired]

        if request.method == 'POST' and expired_list:
            with get_db_transaction() as conn:
                cursor = conn.cursor()
                released = 0
                for row in expired:
                    cursor.execute("UPDATE lan_ips SET username=NULL, reservation_date=NULL, branch_name=NULL, status='Free' WHERE octet2=? AND octet3=? AND status='Reserved'",
                                   (row['octet2'], row['octet3']))
                    cursor.execute("DELETE FROM reserved_ips WHERE id=?", (row['id'],))
                    released += 1
            log_audit('auto_release', f'{released} expired IPs released', 'Admin', 'lan',
                      ip_address=request.remote_addr)
            return jsonify({'success': True, 'released': released, 'message': f'{released} expired IPs released'})

        return jsonify({'success': True, 'expired_count': len(expired_list), 'expired': expired_list})
    except Exception as e:
        return jsonify({'success': False, 'error': sanitize_error(e)}), 500


@lan_bp.route('/api/bulk-reserve-lan', methods=['POST'])
def bulk_reserve_lan():
    """Bulk reserve multiple LAN IPs at once."""
    try:
        data = request.json or {}
        items = data.get('items', [])
        username = data.get('username', '')
        if not items or not username:
            return jsonify({'status': 'error', 'message': 'Missing data'}), 400
        if len(items) > 20:
            return jsonify({'status': 'error', 'message': 'Max 20 items per bulk operation'}), 400

        results = []
        now = datetime.now()
        expiry = now + timedelta(days=Config.RESERVATION_EXPIRY_DAYS)

        with get_db_transaction() as conn:
            cursor = conn.cursor()
            for item in items:
                octet2 = item.get('octet2')
                octet3 = item.get('octet3')
                branch = item.get('branch_name', '')
                province = item.get('province', '')
                if not octet2 or not octet3:
                    results.append({'ip': 'unknown', 'status': 'error', 'message': 'Invalid data'})
                    continue
                cursor.execute("SELECT status FROM lan_ips WHERE octet2=? AND octet3=?", (octet2, octet3))
                row = cursor.fetchone()
                if row and row['status'] and row['status'].lower() in ('reserved', 'used'):
                    results.append({'ip': f'10.{octet2}.{octet3}.0/24', 'status': 'skip', 'message': 'Already reserved'})
                    continue
                cursor.execute("UPDATE lan_ips SET username=?, reservation_date=?, branch_name=?, status='Reserved' WHERE octet2=? AND octet3=?",
                               (username, now.strftime('%Y-%m-%d'), branch, octet2, octet3))
                cursor.execute("""
                    INSERT INTO reserved_ips (province, octet2, octet3, branch_name, username, reservation_date, expiry_date, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'reserved')
                """, (province, octet2, octet3, branch, username, now.strftime('%Y-%m-%d'), expiry.strftime('%Y-%m-%d')))
                results.append({'ip': f'10.{octet2}.{octet3}.0/24', 'status': 'ok'})

        log_audit('bulk_reserve_lan', f'{len([r for r in results if r["status"]=="ok"])} IPs reserved',
                  username, 'lan', ip_address=request.remote_addr)
        return jsonify({'status': 'ok', 'results': results})
    except Exception as e:
        return jsonify({'status': 'error', 'message': sanitize_error(e)}), 500


@lan_bp.route('/api/bulk-release-lan', methods=['POST'])
def bulk_release_lan():
    """Bulk release multiple LAN IPs."""
    try:
        data = request.json or {}
        ips = data.get('ips', [])
        username = data.get('username', '')
        if not ips:
            return jsonify({'status': 'error', 'message': 'No IPs specified'}), 400

        released = 0
        with get_db_transaction() as conn:
            cursor = conn.cursor()
            for ip_str in ips:
                parts = ip_str.replace('/24', '').split('.')
                if len(parts) >= 3:
                    o2, o3 = int(parts[1]), int(parts[2])
                    cursor.execute("UPDATE lan_ips SET username=NULL, reservation_date=NULL, branch_name=NULL, status='Free' WHERE octet2=? AND octet3=?", (o2, o3))
                    cursor.execute("DELETE FROM reserved_ips WHERE octet2=? AND octet3=?", (o2, o3))
                    released += 1

        log_audit('bulk_release_lan', f'{released} IPs released', username, 'lan',
                  ip_address=request.remote_addr)
        return jsonify({'status': 'ok', 'released': released})
    except Exception as e:
        return jsonify({'status': 'error', 'message': sanitize_error(e)}), 500


@lan_bp.route('/api/subnet-calculator', methods=['POST'])
def subnet_calculator():
    """Calculate subnet information from IP/CIDR."""
    data = request.json or {}
    ip_cidr = data.get('ip', '').strip()
    if not ip_cidr:
        return jsonify({'error': 'IP address required'}), 400

    try:
        if '/' in ip_cidr:
            ip_part, cidr = ip_cidr.split('/')
            cidr = int(cidr)
        else:
            ip_part = ip_cidr
            cidr = 24

        octets = [int(o) for o in ip_part.split('.')]
        if len(octets) != 4 or not all(0 <= o <= 255 for o in octets):
            return jsonify({'error': 'Invalid IP'}), 400
        if not 0 <= cidr <= 32:
            return jsonify({'error': 'Invalid CIDR'}), 400

        ip_int = (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3]
        mask_int = (0xFFFFFFFF << (32 - cidr)) & 0xFFFFFFFF
        network_int = ip_int & mask_int
        broadcast_int = network_int | (~mask_int & 0xFFFFFFFF)
        first_host = network_int + 1
        last_host = broadcast_int - 1
        total_hosts = (1 << (32 - cidr)) - 2

        def int_to_ip(n):
            return f"{(n >> 24) & 0xFF}.{(n >> 16) & 0xFF}.{(n >> 8) & 0xFF}.{n & 0xFF}"

        return jsonify({
            'ip': ip_part, 'cidr': cidr,
            'network': int_to_ip(network_int), 'broadcast': int_to_ip(broadcast_int),
            'mask': int_to_ip(mask_int), 'first_host': int_to_ip(first_host),
            'last_host': int_to_ip(last_host), 'total_hosts': max(0, total_hosts),
            'wildcard': int_to_ip(~mask_int & 0xFFFFFFFF)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400
