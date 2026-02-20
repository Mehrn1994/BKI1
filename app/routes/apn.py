"""APN routes - APN INT and APN Mali IP management."""
import sqlite3
from datetime import datetime
from flask import Blueprint, jsonify, request

from app.database import get_db, get_db_readonly, get_db_transaction, log_audit
from app.security import sanitize_error

apn_bp = Blueprint('apn', __name__)


@apn_bp.route('/api/apn-ips', methods=['GET'])
def get_apn_ips():
    try:
        with get_db_readonly() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM apn_ips WHERE (username IS NULL OR username = '')
                ORDER BY id LIMIT 100
            """)
            ips = []
            for row in cursor.fetchall():
                ip_value = None
                for field in ['ip_wan_apn', 'ip', 'ip_wan', 'ip_address']:
                    try:
                        ip_value = row[field]
                        if ip_value:
                            break
                    except Exception:
                        continue
                if ip_value:
                    ips.append({
                        'id': row['id'], 'ip': ip_value,
                        'province': row['province'] if 'province' in row.keys() else '',
                        'branch_name': row['branch_name'] if 'branch_name' in row.keys() else ''
                    })
        return jsonify(ips)
    except Exception:
        return jsonify([])


@apn_bp.route('/api/mali-free-ips', methods=['GET'])
def get_mali_free_ips():
    try:
        with get_db_readonly() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, ip_wan, province, branch_name FROM apn_mali
                WHERE (username IS NULL OR username = '')
                AND ip_wan IS NOT NULL AND ip_wan != ''
                ORDER BY id
            """)
            ips = [{'id': r['id'], 'ip': r['ip_wan'], 'province': r['province'] or '',
                     'branch_name': r['branch_name'] or ''} for r in cursor.fetchall()]
        return jsonify(ips)
    except Exception:
        return jsonify([])


@apn_bp.route('/api/reserve-ips', methods=['POST'])
def reserve_ips():
    try:
        data = request.json or {}
        username = data.get('username')
        branch_name = data.get('branchName')
        lan_ip = data.get('lanIp')
        apn_ip = data.get('apnIp')
        province = data.get('province', '')
        ip_type = data.get('type', 'APN-INT')
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        updates = []

        with get_db_transaction() as conn:
            cursor = conn.cursor()
            if lan_ip:
                parts = lan_ip.replace('/24', '').split('.')
                if len(parts) >= 3:
                    octet2, octet3 = int(parts[1]), int(parts[2])
                    cursor.execute("UPDATE lan_ips SET username=?, reservation_date=?, status='Used' WHERE octet2=? AND octet3=?",
                                   (username, now, octet2, octet3))
                    cursor.execute("""
                        UPDATE reserved_ips SET status='activated', activated_at=?, config_type='APN_INT'
                        WHERE octet2=? AND octet3=? AND (status='reserved' OR status IS NULL)
                    """, (now, octet2, octet3))
                    updates.append(f"LAN IP {lan_ip} activated")

            if apn_ip:
                cursor.execute("""
                    UPDATE apn_ips SET username=?, reservation_date=?, branch_name=?,
                        province=COALESCE(?, province), type=COALESCE(?, type), lan_ip=COALESCE(?, lan_ip)
                    WHERE ip_wan_apn=?
                """, (username, now, branch_name, province, ip_type, lan_ip, apn_ip))
                updates.append(f"APN IP {apn_ip} reserved")

            if branch_name and not lan_ip:
                cursor.execute("UPDATE lan_ips SET status='Used' WHERE branch_name=? AND status='Reserved'", (branch_name,))
                if cursor.rowcount > 0:
                    cursor.execute("""
                        UPDATE reserved_ips SET status='activated', activated_at=?, config_type='APN_INT'
                        WHERE branch_name=? AND (status='reserved' OR status IS NULL)
                    """, (now, branch_name))
                    updates.append(f"LAN IP for {branch_name} activated")

        log_audit('reserve_apn_int', f'{branch_name}: {lan_ip}, {apn_ip}', username, 'apn',
                  ip_address=request.remote_addr)
        return jsonify({'status': 'ok', 'updates': updates})
    except Exception as e:
        return jsonify({'status': 'error', 'error': sanitize_error(e)}), 500


@apn_bp.route('/api/reserve-mali-ips', methods=['POST'])
def reserve_mali_ips():
    try:
        data = request.json or {}
        username = data.get('username')
        branch_name = data.get('branchName')
        apn_ip = data.get('apnIp')
        tunnel_id = data.get('tunnelId')
        tunnel_ip_branch = data.get('tunnelIpBranch')
        tunnel_ip_hub = data.get('tunnelIpHub')
        tunnel_number = data.get('tunnelNumber')
        province = data.get('province', '')
        lan_ip = data.get('lanIp', '')
        interface_name = data.get('interfaceName', f'Tunnel{tunnel_number}')
        description = data.get('description', f'Gilanet-{branch_name}')
        destination_ip = data.get('destinationIp', '')
        node_type = data.get('type', 'APN-MALI')
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        updates = []

        with get_db_transaction() as conn:
            cursor = conn.cursor()
            if apn_ip:
                cursor.execute("""
                    UPDATE apn_mali SET username=?, reservation_date=?, branch_name=?,
                        province=COALESCE(?, province), type=?, lan_ip=COALESCE(?, lan_ip)
                    WHERE ip_wan=?
                """, (username, now, branch_name, province, node_type, lan_ip, apn_ip))
                updates.append(f"APN Mali IP {apn_ip} reserved")

            if tunnel_id:
                cursor.execute("""
                    UPDATE tunnel_mali SET status='Reserved', username=?, branch_name=?,
                        reservation_date=?, interface_name=COALESCE(?, interface_name),
                        description=COALESCE(?, description), ip_address=COALESCE(?, ip_address),
                        hub_ip=COALESCE(?, hub_ip), branch_ip=COALESCE(?, branch_ip),
                        destination_ip=COALESCE(?, destination_ip)
                    WHERE id=?
                """, (username, branch_name, now, interface_name, description,
                      tunnel_ip_branch, tunnel_ip_hub, tunnel_ip_branch, destination_ip, tunnel_id))
                updates.append("Tunnel Mali reserved")

            if branch_name:
                cursor.execute("UPDATE lan_ips SET status='Used' WHERE branch_name=? AND status='Reserved'", (branch_name,))
                if cursor.rowcount > 0:
                    cursor.execute("""
                        UPDATE reserved_ips SET status='activated', activated_at=?, config_type='APN_MALI'
                        WHERE branch_name=? AND (status='reserved' OR status IS NULL)
                    """, (now, branch_name))
                    updates.append(f"LAN IP for {branch_name} activated")

        log_audit('reserve_apn_mali', f'{branch_name}: {apn_ip}, Tunnel: {tunnel_number}', username, 'apn',
                  ip_address=request.remote_addr)
        return jsonify({'status': 'ok', 'updates': updates, 'message': f'All fields saved for {branch_name}'})
    except Exception as e:
        return jsonify({'status': 'error', 'error': sanitize_error(e)}), 500


@apn_bp.route('/api/mali-reserved-points')
def mali_reserved_points():
    try:
        with get_db_readonly() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, branch_name, province, type, lan_ip, ip_wan, username, reservation_date
                FROM apn_mali WHERE username IS NOT NULL AND username != ''
                ORDER BY reservation_date DESC
            """)
            return jsonify([{
                'id': r[0], 'branch_name': r[1], 'province': r[2], 'type': r[3],
                'lan_ip': r[4], 'ip_wan': r[5], 'username': r[6], 'reservation_date': r[7]
            } for r in cursor.fetchall()])
    except Exception:
        return jsonify([])


@apn_bp.route('/api/int-reserved-points')
def int_reserved_points():
    try:
        with get_db_readonly() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, branch_name, province, type, lan_ip, ip_wan_apn, username, reservation_date
                FROM apn_ips WHERE username IS NOT NULL AND username != ''
                ORDER BY reservation_date DESC
            """)
            return jsonify([{
                'id': r[0], 'branch_name': r[1], 'province': r[2], 'type': r[3],
                'lan_ip': r[4], 'ip_wan_apn': r[5], 'username': r[6], 'reservation_date': r[7]
            } for r in cursor.fetchall()])
    except Exception:
        return jsonify([])


@apn_bp.route('/api/free-mali-point', methods=['POST'])
def free_mali_point():
    try:
        data = request.json or {}
        point_id = data.get('id')
        username = data.get('username', '')
        if not point_id:
            return jsonify({'status': 'error', 'error': 'Point ID required'}), 400

        with get_db_transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT branch_name, ip_wan, lan_ip FROM apn_mali WHERE id=?", (point_id,))
            point = cursor.fetchone()
            if not point:
                return jsonify({'status': 'error', 'error': 'Point not found'}), 404

            branch_name, ip_wan = point[0], point[1]
            updates = []
            cursor.execute("""
                UPDATE apn_mali SET username=NULL, branch_name=NULL, province=NULL,
                type=NULL, lan_ip=NULL, reservation_date=NULL WHERE id=?
            """, (point_id,))
            updates.append(f'APN Mali IP released: {ip_wan}')

            cursor.execute("""
                UPDATE tunnel_mali SET status=NULL, username=NULL, branch_name=NULL,
                reservation_date=NULL, description=NULL, destination_ip=NULL
                WHERE destination_ip=?
            """, (ip_wan,))
            if cursor.rowcount > 0:
                updates.append('Associated tunnel released')

        log_audit('free_mali_point', f'{branch_name}: {ip_wan}', username, 'apn',
                  ip_address=request.remote_addr)
        return jsonify({'status': 'ok', 'updates': updates, 'message': f'Point {branch_name} released'})
    except Exception as e:
        return jsonify({'status': 'error', 'error': sanitize_error(e)}), 500


@apn_bp.route('/api/free-int-point', methods=['POST'])
def free_int_point():
    try:
        data = request.json or {}
        point_id = data.get('id')
        username = data.get('username', '')
        if not point_id:
            return jsonify({'status': 'error', 'error': 'Point ID required'}), 400

        with get_db_transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT branch_name, ip_wan_apn, lan_ip FROM apn_ips WHERE id=?", (point_id,))
            point = cursor.fetchone()
            if not point:
                return jsonify({'status': 'error', 'error': 'Point not found'}), 404

            branch_name, ip_wan_apn = point[0], point[1]
            updates = []
            cursor.execute("""
                UPDATE apn_ips SET username=NULL, branch_name=NULL, province=NULL,
                type=NULL, lan_ip=NULL, reservation_date=NULL WHERE id=?
            """, (point_id,))
            updates.append(f'APN INT IP released: {ip_wan_apn}')

            cursor.execute("""
                UPDATE tunnel200_ips SET status=NULL, username=NULL, branch_name=NULL,
                reservation_date=NULL, description=NULL WHERE branch_name=?
            """, (branch_name,))
            if cursor.rowcount > 0:
                updates.append('Associated Tunnel200 released')

        log_audit('free_int_point', f'{branch_name}: {ip_wan_apn}', username, 'apn',
                  ip_address=request.remote_addr)
        return jsonify({'status': 'ok', 'updates': updates, 'message': f'Point {branch_name} released'})
    except Exception as e:
        return jsonify({'status': 'error', 'error': sanitize_error(e)}), 500
