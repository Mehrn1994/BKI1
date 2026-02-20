"""Service management and PTMP routes."""
from datetime import datetime
from flask import Blueprint, jsonify, request

from app.database import get_db, get_db_readonly, get_db_transaction, log_audit
from app.security import is_api_rate_limited, validate_table_name, sanitize_error

services_bp = Blueprint('services', __name__)


@services_bp.route('/api/search-services', methods=['GET'])
def search_services():
    try:
        query = request.args.get('q', '').strip()
        search_type = request.args.get('type', 'branch_name')
        if not query or len(query) < 2:
            return jsonify([])

        like_q = f'%{query}%'
        results = []

        def add_result(row_tuple, table, service):
            results.append({
                'id': row_tuple[0], 'table': table, 'service': service,
                'branch_name': row_tuple[1] or '', 'province': row_tuple[2] or '',
                'ip': row_tuple[3] or '', 'lan_ip': row_tuple[4] or '',
                'username': row_tuple[5] or '', 'date': row_tuple[6] or ''
            })

        with get_db_readonly() as conn:
            cursor = conn.cursor()

            if search_type == 'branch_name':
                _search_by_branch(cursor, like_q, add_result)
            elif search_type == 'ip_apn_mali':
                cursor.execute("SELECT id, branch_name, province, ip_wan, lan_ip, username, reservation_date FROM apn_mali WHERE ip_wan LIKE ? AND branch_name IS NOT NULL AND branch_name != ''", (like_q,))
                for r in cursor.fetchall(): add_result(r, 'apn_mali', 'APN Mali')
            elif search_type == 'ip_apn_int':
                cursor.execute("SELECT id, branch_name, province, ip_wan_apn, lan_ip, username, reservation_date FROM apn_ips WHERE ip_wan_apn LIKE ? AND branch_name IS NOT NULL AND branch_name != ''", (like_q,))
                for r in cursor.fetchall(): add_result(r, 'apn_ips', 'APN INT')
            elif search_type == 'ip_lan':
                _search_by_lan_ip(cursor, like_q, add_result)
            elif search_type == 'ip_intranet':
                cursor.execute("SELECT id, tunnel_name, province, ip_address, ip_lan, reserved_by, reserved_at FROM intranet_tunnels WHERE (ip_address LIKE ? OR ip_intranet LIKE ?) AND LOWER(status)='reserved'", (like_q, like_q))
                for r in cursor.fetchall(): add_result(r, 'intranet_tunnels', 'Intranet')
            elif search_type == 'ip_vpls':
                cursor.execute("SELECT id, branch_name, province, ip_address, wan_ip, username, reservation_date FROM vpls_tunnels WHERE (ip_address LIKE ? OR wan_ip LIKE ?) AND LOWER(status)='reserved'", (like_q, like_q))
                for r in cursor.fetchall(): add_result(r, 'vpls_tunnels', 'MPLS/VPLS')
            elif search_type == 'ip_ptmp':
                try:
                    cursor.execute("SELECT id, COALESCE(branch_name, branch_name_en), province, interface_name, lan_ip, username, reservation_date FROM ptmp_connections WHERE (interface_name LIKE ? OR description LIKE ? OR branch_name LIKE ? OR branch_name_en LIKE ?) AND (branch_name IS NOT NULL OR branch_name_en IS NOT NULL)", (like_q, like_q, like_q, like_q))
                    for r in cursor.fetchall(): add_result(r, 'ptmp_connections', 'PTMP Serial')
                except Exception:
                    pass

        return jsonify(results)
    except Exception:
        return jsonify([])


def _search_by_branch(cursor, like_q, add_result):
    cursor.execute("SELECT id, branch_name, province, '10.' || octet2 || '.' || octet3 || '.0/24', wan_ip, username, reservation_date FROM lan_ips WHERE branch_name LIKE ? AND branch_name IS NOT NULL AND branch_name != '' AND status != 'Free'", (like_q,))
    for r in cursor.fetchall(): add_result(r, 'lan_ips', 'IP LAN')

    cursor.execute("SELECT id, branch_name, province, ip_wan, lan_ip, username, reservation_date FROM apn_mali WHERE branch_name LIKE ? AND branch_name IS NOT NULL AND branch_name != ''", (like_q,))
    for r in cursor.fetchall(): add_result(r, 'apn_mali', 'APN Mali')

    cursor.execute("SELECT id, branch_name, province, ip_wan_apn, lan_ip, username, reservation_date FROM apn_ips WHERE branch_name LIKE ? AND branch_name IS NOT NULL AND branch_name != ''", (like_q,))
    for r in cursor.fetchall(): add_result(r, 'apn_ips', 'APN INT')

    cursor.execute("SELECT id, tunnel_name, province, ip_address, ip_lan, reserved_by, reserved_at FROM intranet_tunnels WHERE (tunnel_name LIKE ? OR description LIKE ?) AND LOWER(status)='reserved'", (like_q, like_q))
    for r in cursor.fetchall(): add_result(r, 'intranet_tunnels', 'Intranet')

    cursor.execute("SELECT id, branch_name, province, ip_address, wan_ip, username, reservation_date FROM vpls_tunnels WHERE branch_name LIKE ? AND LOWER(status)='reserved'", (like_q,))
    for r in cursor.fetchall(): add_result(r, 'vpls_tunnels', 'MPLS/VPLS')

    cursor.execute("SELECT id, branch_name, '', ip_address, '', username, reservation_date FROM tunnel_mali WHERE branch_name LIKE ? AND branch_name IS NOT NULL AND branch_name != ''", (like_q,))
    for r in cursor.fetchall(): add_result(r, 'tunnel_mali', 'Tunnel Mali')

    cursor.execute("SELECT id, branch_name, '', ip_address, '', username, reservation_date FROM tunnel200_ips WHERE branch_name LIKE ? AND branch_name IS NOT NULL AND branch_name != ''", (like_q,))
    for r in cursor.fetchall(): add_result(r, 'tunnel200_ips', 'Tunnel200')

    try:
        cursor.execute("SELECT id, COALESCE(branch_name, branch_name_en), province, interface_name, lan_ip, username, reservation_date FROM ptmp_connections WHERE (branch_name LIKE ? OR branch_name_en LIKE ?) AND (branch_name IS NOT NULL OR branch_name_en IS NOT NULL)", (like_q, like_q))
        for r in cursor.fetchall(): add_result(r, 'ptmp_connections', 'PTMP Serial')
    except Exception:
        pass


def _search_by_lan_ip(cursor, like_q, add_result):
    cursor.execute("SELECT id, branch_name, province, '10.' || octet2 || '.' || octet3 || '.0/24', wan_ip, username, reservation_date FROM lan_ips WHERE ('10.' || octet2 || '.' || octet3 || '.0/24') LIKE ? AND branch_name IS NOT NULL AND branch_name != '' AND status != 'Free'", (like_q,))
    for r in cursor.fetchall(): add_result(r, 'lan_ips', 'IP LAN')

    cursor.execute("SELECT id, branch_name, province, ip_wan, lan_ip, username, reservation_date FROM apn_mali WHERE lan_ip LIKE ? AND branch_name IS NOT NULL AND branch_name != ''", (like_q,))
    for r in cursor.fetchall(): add_result(r, 'apn_mali', 'APN Mali')

    cursor.execute("SELECT id, branch_name, province, ip_wan_apn, lan_ip, username, reservation_date FROM apn_ips WHERE lan_ip LIKE ? AND branch_name IS NOT NULL AND branch_name != ''", (like_q,))
    for r in cursor.fetchall(): add_result(r, 'apn_ips', 'APN INT')

    cursor.execute("SELECT id, tunnel_name, province, ip_address, ip_lan, reserved_by, reserved_at FROM intranet_tunnels WHERE ip_lan LIKE ? AND LOWER(status)='reserved'", (like_q,))
    for r in cursor.fetchall(): add_result(r, 'intranet_tunnels', 'Intranet')

    try:
        cursor.execute("SELECT id, COALESCE(branch_name, branch_name_en), province, interface_name, lan_ip, username, reservation_date FROM ptmp_connections WHERE lan_ip LIKE ? AND (branch_name IS NOT NULL OR branch_name_en IS NOT NULL)", (like_q,))
        for r in cursor.fetchall(): add_result(r, 'ptmp_connections', 'PTMP Serial')
    except Exception:
        pass


@services_bp.route('/api/delete-service', methods=['POST'])
def delete_service():
    try:
        if is_api_rate_limited(request.remote_addr, 'delete-service'):
            return jsonify({'status': 'error', 'error': 'Too many requests'}), 429
        data = request.json or {}
        table = data.get('table', '')
        record_id = data.get('id')
        username = data.get('username', '')

        if not table or not record_id:
            return jsonify({'status': 'error', 'error': 'Missing parameters'}), 400

        allowed_tables = ['lan_ips', 'apn_mali', 'apn_ips', 'intranet_tunnels', 'vpls_tunnels', 'tunnel_mali', 'tunnel200_ips', 'ptmp_connections']
        if table not in allowed_tables:
            return jsonify({'status': 'error', 'error': 'Invalid table'}), 400

        with get_db_transaction() as conn:
            cursor = conn.cursor()
            # Safe: table name is validated against whitelist above
            cursor.execute(f"SELECT * FROM {table} WHERE id = ?", (record_id,))
            row = cursor.fetchone()
            if not row:
                return jsonify({'status': 'error', 'error': 'Record not found'}), 404

            if table == 'lan_ips':
                octet2, octet3 = row['octet2'], row['octet3']
                cursor.execute("UPDATE lan_ips SET username=NULL, reservation_date=NULL, branch_name=NULL, status='Free', notes=NULL, wan_ip=NULL WHERE id=?", (record_id,))
                cursor.execute("DELETE FROM reserved_ips WHERE octet2=? AND octet3=?", (octet2, octet3))
                log_audit('delete_service', f"LAN IP: 10.{octet2}.{octet3}.0/24", username, 'service', table, record_id, ip_address=request.remote_addr)
            elif table == 'apn_mali':
                ip = row['ip_wan'] or ''
                cursor.execute("UPDATE apn_mali SET username=NULL, branch_name=NULL, province=NULL, type=NULL, lan_ip=NULL, reservation_date=NULL WHERE id=?", (record_id,))
                if ip:
                    cursor.execute("UPDATE tunnel_mali SET status=NULL, username=NULL, branch_name=NULL, reservation_date=NULL, description=NULL, destination_ip=NULL WHERE destination_ip=?", (ip,))
                log_audit('delete_service', f"APN Mali: {ip}", username, 'service', table, record_id, ip_address=request.remote_addr)
            elif table == 'apn_ips':
                branch = row['branch_name'] or ''
                cursor.execute("UPDATE apn_ips SET username=NULL, branch_name=NULL, province=NULL, type=NULL, lan_ip=NULL, reservation_date=NULL WHERE id=?", (record_id,))
                if branch:
                    cursor.execute("UPDATE tunnel200_ips SET status=NULL, username=NULL, branch_name=NULL, reservation_date=NULL, description=NULL WHERE branch_name=?", (branch,))
                log_audit('delete_service', f"APN INT: {branch}", username, 'service', table, record_id, ip_address=request.remote_addr)
            elif table == 'intranet_tunnels':
                cursor.execute("UPDATE intranet_tunnels SET status='Free', reserved_by=NULL, reserved_at=NULL, tunnel_name=NULL, description=NULL, ip_lan=NULL, ip_intranet=NULL WHERE id=?", (record_id,))
                log_audit('delete_service', f"Intranet: {row['tunnel_name'] or ''}", username, 'service', table, record_id, ip_address=request.remote_addr)
            elif table == 'vpls_tunnels':
                cursor.execute("UPDATE vpls_tunnels SET status='Free', username=NULL, branch_name=NULL, tunnel_name=NULL, description=NULL, wan_ip=NULL, tunnel_dest=NULL, reservation_date=NULL WHERE id=?", (record_id,))
                log_audit('delete_service', f"VPLS: {row['branch_name'] or ''}", username, 'service', table, record_id, ip_address=request.remote_addr)
            elif table == 'tunnel_mali':
                cursor.execute("UPDATE tunnel_mali SET status=NULL, username=NULL, branch_name=NULL, reservation_date=NULL, description=NULL, destination_ip=NULL WHERE id=?", (record_id,))
                log_audit('delete_service', f"Tunnel Mali: {row['branch_name'] or ''}", username, 'service', table, record_id, ip_address=request.remote_addr)
            elif table == 'tunnel200_ips':
                cursor.execute("UPDATE tunnel200_ips SET status=NULL, username=NULL, branch_name=NULL, reservation_date=NULL, description=NULL WHERE id=?", (record_id,))
                log_audit('delete_service', f"Tunnel200: {row['branch_name'] or ''}", username, 'service', table, record_id, ip_address=request.remote_addr)
            elif table == 'ptmp_connections':
                cursor.execute("DELETE FROM ptmp_connections WHERE id=?", (record_id,))
                log_audit('delete_service', f"PTMP: {row['branch_name'] or ''}", username, 'service', table, record_id, ip_address=request.remote_addr)

        return jsonify({'status': 'ok', 'message': 'Service deleted successfully'})
    except Exception as e:
        return jsonify({'status': 'error', 'error': sanitize_error(e)}), 500


# ===== PTMP =====
@services_bp.route('/api/save-ptmp', methods=['POST'])
def save_ptmp():
    try:
        data = request.json or {}
        branch_name = data.get('branchName', '').strip()
        hostname = data.get('hostname', '').strip()
        province = data.get('province', '').strip()
        lan_ip = data.get('lanIp', '').strip()
        serial_port = data.get('serialPort', '').strip() or 'Serial0/0/0'
        username = data.get('username', '').strip()

        if not hostname or not lan_ip:
            return jsonify({'status': 'error', 'error': 'Hostname and LAN IP required'}), 400

        conn = get_db()
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        desc = f'** {branch_name} - PTMP **' if branch_name else '** PTMP **'
        conn.execute("""
            INSERT INTO ptmp_connections (interface_name, description, branch_name, branch_name_en,
                bandwidth, ip_type, encapsulation, province, province_abbr, router_hostname, router_file,
                status, username, reservation_date, lan_ip)
            VALUES (?, ?, ?, ?, '64', 'unnumbered', 'ppp', ?, '', ?, 'manual', 'Manual', ?, ?, ?)
        """, (serial_port, desc, branch_name or None, branch_name or None, province, hostname, username, now, lan_ip))
        conn.commit()
        conn.close()

        log_audit('save_ptmp', f'{branch_name}: {hostname} ({serial_port})', username, 'ptmp',
                  ip_address=request.remote_addr)
        return jsonify({'status': 'ok', 'message': f'PTMP saved for {branch_name or hostname}'})
    except Exception as e:
        return jsonify({'status': 'error', 'error': sanitize_error(e)}), 500


@services_bp.route('/api/import-ptmp', methods=['POST'])
def import_ptmp_from_configs():
    try:
        username = request.json.get('username', 'system') if request.json else 'system'
        from parse_router_configs import import_serial_to_db
        count = import_serial_to_db()
        log_audit('import_ptmp', f'{count} Serial interfaces imported', username, 'ptmp',
                  ip_address=request.remote_addr)
        return jsonify({'status': 'ok', 'count': count})
    except Exception as e:
        return jsonify({'status': 'error', 'error': sanitize_error(e)}), 500


@services_bp.route('/api/ptmp-stats', methods=['GET'])
def ptmp_stats():
    try:
        with get_db_readonly() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT province, province_abbr, COUNT(*) as total,
                    SUM(CASE WHEN branch_name IS NOT NULL THEN 1 ELSE 0 END) as matched,
                    SUM(CASE WHEN branch_name_en IS NOT NULL THEN 1 ELSE 0 END) as with_branch
                FROM ptmp_connections GROUP BY province ORDER BY total DESC
            """)
            stats = [{'province': r['province'] or '', 'province_abbr': r['province_abbr'] or '',
                       'total': r['total'], 'matched': r['matched'], 'with_branch': r['with_branch']}
                     for r in cursor.fetchall()]
        return jsonify(stats)
    except Exception:
        return jsonify([])


@services_bp.route('/api/problematic-nodes', methods=['GET'])
def get_problematic_nodes():
    return jsonify({'success': True, 'nodes': [], 'message': 'Run monitoring scan to get real data'})
