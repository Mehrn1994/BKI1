"""Tunnel routes - Intranet, VPLS/MPLS, Tunnel Mali, Tunnel200."""
import os
import time
from datetime import datetime
from flask import Blueprint, jsonify, request

from app.config import Config
from app.database import get_db, get_db_readonly, get_db_transaction, log_audit
from app.security import sanitize_error

tunnels_bp = Blueprint('tunnels', __name__)

# Excel tunnel cache
_excel_tunnel_cache = {'data': None, 'loaded': False, 'time': 0}
EXCEL_CACHE_TTL = 1800


def _load_excel_tunnel_data():
    if _excel_tunnel_cache['loaded'] and (time.time() - _excel_tunnel_cache['time']) < EXCEL_CACHE_TTL:
        return _excel_tunnel_cache['data']
    try:
        import pandas as pd
        excel_path = os.path.join(Config.BASE_DIR, 'data', 'VPLS_MPLS_Tunnel_IPs.xlsx')
        if os.path.exists(excel_path):
            df = pd.read_excel(excel_path, sheet_name='All_Tunnels')
            all_ips = set()
            for col in ['tunnel_source', 'tunnel_destination']:
                for ip in df[col].dropna():
                    ip_str = str(ip).strip()
                    if ip_str and ip_str[0].isdigit():
                        all_ips.add(ip_str)
            _excel_tunnel_cache.update({'data': all_ips, 'loaded': True, 'time': time.time()})
            return all_ips
    except Exception:
        pass
    _excel_tunnel_cache.update({'data': set(), 'loaded': True, 'time': time.time()})
    return set()


# ===== INTRANET TUNNELS =====
@tunnels_bp.route('/tunnels', methods=['GET'])
@tunnels_bp.route('/api/tunnels', methods=['GET'])
def get_tunnels():
    try:
        with get_db_readonly() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM intranet_tunnels WHERE LOWER(status) = 'free'
                ORDER BY province, tunnel_name
            """)
            tunnels = []
            for row in cursor.fetchall():
                tunnels.append({
                    'IP Address': row['ip_address'], 'Tunnel Name': row['tunnel_name'] or '',
                    'IP LAN': row['ip_lan'] or '', 'IP Intranet': row['ip_intranet'] or '',
                    'Description': row['description'] or '', 'Province': row['province'] or '',
                    'Status': row['status'] or ''
                })
        return jsonify(tunnels)
    except Exception:
        return jsonify([])


@tunnels_bp.route('/reserve', methods=['POST'])
def reserve_tunnel():
    try:
        data = request.json or {}
        ip_address = data.get('IP Address')
        username = data.get('by')
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        with get_db_transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE intranet_tunnels SET status='Reserved', reserved_by=?, reserved_at=?,
                    tunnel_name=COALESCE(?, tunnel_name), ip_lan=COALESCE(?, ip_lan),
                    ip_intranet=COALESCE(?, ip_intranet), description=COALESCE(?, description),
                    province=COALESCE(?, province)
                WHERE ip_address=?
            """, (username, now, data.get('Tunnel Name'), data.get('IP LAN'),
                  data.get('IP Intranet'), data.get('Description'), data.get('Province'), ip_address))

        log_audit('reserve_tunnel', ip_address, username, 'intranet', ip_address=request.remote_addr)
        return jsonify({'status': 'ok'})
    except Exception as e:
        return jsonify({'status': 'error', 'error': sanitize_error(e)}), 500


@tunnels_bp.route('/api/check-tunnel-name', methods=['POST'])
def check_tunnel_name():
    try:
        data = request.json or {}
        tunnel_name = data.get('tunnel_name', '').strip()
        if not tunnel_name:
            return jsonify({'status': 'error', 'error': 'Tunnel name required'}), 400
        with get_db_readonly() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, ip_address, description, reserved_by, status
                FROM intranet_tunnels WHERE tunnel_name=? AND LOWER(status)!='free'
            """, (tunnel_name,))
            row = cursor.fetchone()
        if row:
            return jsonify({'exists': True, 'ip_address': row['ip_address'] or '',
                            'description': row['description'] or '', 'reserved_by': row['reserved_by'] or '',
                            'status': row['status'] or ''})
        return jsonify({'exists': False})
    except Exception as e:
        return jsonify({'status': 'error', 'error': sanitize_error(e)}), 500


@tunnels_bp.route('/api/reserved-intranet', methods=['GET'])
def get_reserved_intranet():
    try:
        q = request.args.get('q', '').strip()
        with get_db_readonly() as conn:
            cursor = conn.cursor()
            if q:
                like_q = f'%{q}%'
                cursor.execute("""
                    SELECT id, ip_address, tunnel_name, ip_lan, ip_intranet, description, province, reserved_by, reserved_at
                    FROM intranet_tunnels WHERE LOWER(status)='reserved'
                    AND (tunnel_name LIKE ? OR description LIKE ? OR province LIKE ? OR ip_address LIKE ? OR ip_lan LIKE ?)
                    ORDER BY reserved_at DESC
                """, (like_q, like_q, like_q, like_q, like_q))
            else:
                cursor.execute("""
                    SELECT id, ip_address, tunnel_name, ip_lan, ip_intranet, description, province, reserved_by, reserved_at
                    FROM intranet_tunnels WHERE LOWER(status)='reserved' ORDER BY reserved_at DESC
                """)
            results = [{
                'id': r[0], 'ip_address': r[1] or '', 'tunnel_name': r[2] or '',
                'ip_lan': r[3] or '', 'ip_intranet': r[4] or '', 'description': r[5] or '',
                'province': r[6] or '', 'reserved_by': r[7] or '', 'reserved_at': r[8] or ''
            } for r in cursor.fetchall()]
        return jsonify(results)
    except Exception:
        return jsonify([])


# ===== VPLS/MPLS =====
@tunnels_bp.route('/api/vpls-tunnels', methods=['GET'])
def get_vpls_tunnels():
    try:
        province = request.args.get('province', '').strip()
        with get_db_readonly() as conn:
            cursor = conn.cursor()
            if province:
                cursor.execute("""
                    SELECT id, ip_address, hub_ip, branch_ip, tunnel_name, description, province, status
                    FROM vpls_tunnels WHERE LOWER(status)='free' AND province=? ORDER BY id
                """, (province,))
            else:
                cursor.execute("""
                    SELECT id, ip_address, hub_ip, branch_ip, tunnel_name, description, province, status
                    FROM vpls_tunnels WHERE LOWER(status)='free' ORDER BY id
                """)
            tunnels = [{
                'id': r['id'], 'ip_address': r['ip_address'], 'hub_ip': r['hub_ip'],
                'branch_ip': r['branch_ip'], 'tunnel_name': r['tunnel_name'] or '',
                'description': r['description'] or '', 'province': r['province'] or '',
                'status': r['status']
            } for r in cursor.fetchall()]
        return jsonify(tunnels)
    except Exception:
        return jsonify([])


@tunnels_bp.route('/api/reserve-vpls-tunnel', methods=['POST'])
def reserve_vpls_tunnel():
    try:
        data = request.json or {}
        tunnel_id = data.get('id')
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        username = data.get('username', '')

        with get_db_transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE vpls_tunnels SET status='Reserved', tunnel_name=?, description=?,
                    province=?, branch_name=?, wan_ip=?, tunnel_dest=?, username=?, reservation_date=?
                WHERE id=? AND LOWER(status)='free'
            """, (data.get('tunnel_name', ''), data.get('description', ''),
                  data.get('province', ''), data.get('branch_name', ''),
                  data.get('wan_ip', ''), data.get('tunnel_dest', ''),
                  username, now, tunnel_id))
            if cursor.rowcount == 0:
                return jsonify({'status': 'error', 'error': 'Tunnel already reserved or not found'}), 400

        log_audit('reserve_vpls', data.get('tunnel_name', ''), username, 'vpls', ip_address=request.remote_addr)
        return jsonify({'status': 'ok'})
    except Exception as e:
        return jsonify({'status': 'error', 'error': sanitize_error(e)}), 500


@tunnels_bp.route('/api/tunnel-template', methods=['GET'])
def get_tunnel_template():
    province_abbr = request.args.get('province_abbr', '').strip()
    service_type = request.args.get('service_type', 'VPLS').strip().upper()

    if province_abbr not in Config.PROVINCE_TUNNEL_TEMPLATES:
        return jsonify({'available': False, 'message': 'No template for this province'})

    template = Config.PROVINCE_TUNNEL_TEMPLATES[province_abbr]
    svc_key = 'vpls' if service_type == 'VPLS' else 'mpls'
    hub_ip = template[svc_key]['hub']
    subnet_prefix = template[svc_key]['subnet']

    used_ips = set()
    excel_ips = _load_excel_tunnel_data()
    for ip in excel_ips:
        if ip.startswith(subnet_prefix + '.'):
            used_ips.add(ip)

    try:
        with get_db_readonly() as conn:
            cursor = conn.cursor()
            like_pattern = subnet_prefix + '.%'
            cursor.execute("SELECT wan_ip, tunnel_dest FROM vpls_tunnels WHERE wan_ip LIKE ? OR tunnel_dest LIKE ?",
                           (like_pattern, like_pattern))
            for row in cursor.fetchall():
                for val in [row['wan_ip'], row['tunnel_dest']]:
                    if val and str(val).startswith(subnet_prefix + '.'):
                        used_ips.add(str(val))
    except Exception:
        pass

    used_last_octets = {0, 255}
    for ip in used_ips:
        parts = ip.split('.')
        if len(parts) == 4:
            try:
                used_last_octets.add(int(parts[3]))
            except ValueError:
                pass
    hub_parts = hub_ip.split('.')
    if len(hub_parts) == 4:
        try:
            used_last_octets.add(int(hub_parts[3]))
        except ValueError:
            pass

    next_free_ip = None
    for i in range(3, 255):
        if i not in used_last_octets:
            next_free_ip = f'{subnet_prefix}.{i}'
            break

    return jsonify({
        'available': True, 'hub_ip': hub_ip, 'branch_subnet': subnet_prefix + '.0/24',
        'next_free_ip': next_free_ip, 'used_ips': sorted(list(used_ips)),
        'used_count': len(used_ips), 'total_capacity': 252,
        'remaining': max(0, 253 - len(used_last_octets)),
        'service_type': service_type, 'province_abbr': province_abbr
    })


# ===== TUNNEL200 =====
@tunnels_bp.route('/api/tunnel200-ips', methods=['GET'])
def get_tunnel200_ips():
    try:
        with get_db_readonly() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM tunnel200_ips
                WHERE status IS NULL OR status = '' OR LOWER(status) = 'free'
                ORDER BY id LIMIT 100
            """)
            ips = []
            for row in cursor.fetchall():
                ips.append({
                    'id': row['id'],
                    'hub_ip': row['hub_ip'] if 'hub_ip' in row.keys() else '',
                    'branch_ip': row['branch_ip'] if 'branch_ip' in row.keys() else '',
                    'pair': row['pair_notation'] if 'pair_notation' in row.keys() else '',
                    'pair_notation': row['pair_notation'] if 'pair_notation' in row.keys() else '',
                    'tunnel_number': row['tunnel_number'] if 'tunnel_number' in row.keys() else '',
                    'interface_name': row['interface_name'] if 'interface_name' in row.keys() else '',
                    'description': row['description'] if 'description' in row.keys() else '',
                    'status': row['status'] if 'status' in row.keys() else ''
                })
        return jsonify(ips)
    except Exception:
        return jsonify([])


@tunnels_bp.route('/api/reserve-tunnel200', methods=['POST'])
def reserve_tunnel200():
    try:
        data = request.json or {}
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        username = data.get('username', '')

        with get_db_transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE tunnel200_ips SET status='Reserved', username=?, branch_name=?,
                    tunnel_number=?, interface_name=?, description=?, reservation_date=?
                WHERE hub_ip=? AND branch_ip=?
            """, (username, data.get('branch_name', ''), data.get('tunnel_number', ''),
                  data.get('interface_name', f"Tunnel{data.get('tunnel_number', '')}"),
                  data.get('description', f"APN-INT-{data.get('branch_name', '')}"),
                  now, data.get('hub_ip'), data.get('branch_ip')))

        log_audit('reserve_tunnel200', f"{data.get('hub_ip')}/{data.get('branch_ip')}", username, 'tunnel200',
                  ip_address=request.remote_addr)
        return jsonify({'status': 'ok'})
    except Exception as e:
        return jsonify({'status': 'error', 'error': sanitize_error(e)}), 500


# ===== TUNNEL MALI =====
@tunnels_bp.route('/api/free-tunnel-pairs', methods=['GET'])
def get_free_tunnel_pairs():
    try:
        with get_db_readonly() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM tunnel_mali
                WHERE status IS NULL OR status = '' OR LOWER(status) = 'free'
                ORDER BY id
            """)
            ips = []
            for row in cursor.fetchall():
                interface = row['interface_name'] or ''
                tunnel_num = ''.join(filter(str.isdigit, interface))
                ip_addr = row['ip_address'] or ''
                hub_ip = ''
                branch_ip = ''
                try:
                    hub_ip = row['hub_ip'] or ''
                    branch_ip = row['branch_ip'] or ''
                except Exception:
                    pass
                if not hub_ip or not branch_ip:
                    base_ip = ip_addr.replace('/31', '').strip()
                    parts = base_ip.split('.')
                    if len(parts) == 4:
                        last_octet = int(parts[3])
                        if last_octet % 2 == 0:
                            hub_ip = base_ip
                            branch_ip = f"{parts[0]}.{parts[1]}.{parts[2]}.{last_octet + 1}"
                        else:
                            branch_ip = base_ip
                            hub_ip = f"{parts[0]}.{parts[1]}.{parts[2]}.{last_octet - 1}"
                ips.append({
                    'id': row['id'], 'tunnel_number': tunnel_num,
                    'tunnel_ip_hub': hub_ip, 'tunnel_ip_branch': branch_ip,
                    'interface_name': interface, 'description': row['description'] or '',
                    'ip_address': ip_addr, 'destination_ip': row['destination_ip'] or ''
                })
        return jsonify(ips)
    except Exception:
        return jsonify([])


@tunnels_bp.route('/api/reserve-tunnel', methods=['POST'])
def reserve_tunnel_mali():
    try:
        data = request.json or {}
        tunnel_id = data.get('tunnel_id') or data.get('id')
        tunnel_number = data.get('tunnel_number') or data.get('tunnelNumber')
        username = data.get('username', '')
        branch_name = data.get('branch_name') or data.get('branchName', '')
        interface_name = data.get('interface_name') or data.get('interfaceName', '')
        description = data.get('description', '')
        hub_ip = data.get('hub_ip') or data.get('hubIp', '')
        branch_ip = data.get('branch_ip') or data.get('branchIp', '')
        destination_ip = data.get('destination_ip') or data.get('destinationIp', '')
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        with get_db_transaction() as conn:
            cursor = conn.cursor()
            rows_updated = 0
            update_params = (username, branch_name, now, interface_name, description,
                             hub_ip, branch_ip, destination_ip)

            if tunnel_id:
                cursor.execute("""
                    UPDATE tunnel_mali SET status='Reserved', username=?, branch_name=?,
                        reservation_date=?, interface_name=COALESCE(NULLIF(?, ''), interface_name),
                        description=COALESCE(NULLIF(?, ''), description),
                        hub_ip=COALESCE(NULLIF(?, ''), hub_ip),
                        branch_ip=COALESCE(NULLIF(?, ''), branch_ip),
                        destination_ip=COALESCE(NULLIF(?, ''), destination_ip)
                    WHERE id=?
                """, (*update_params, tunnel_id))
                rows_updated = cursor.rowcount
            elif tunnel_number:
                cursor.execute("""
                    UPDATE tunnel_mali SET status='Reserved', username=?, branch_name=?,
                        reservation_date=?, interface_name=COALESCE(NULLIF(?, ''), interface_name),
                        description=COALESCE(NULLIF(?, ''), description),
                        hub_ip=COALESCE(NULLIF(?, ''), hub_ip),
                        branch_ip=COALESCE(NULLIF(?, ''), branch_ip),
                        destination_ip=COALESCE(NULLIF(?, ''), destination_ip)
                    WHERE (interface_name=? OR interface_name LIKE ? OR interface_name LIKE ?)
                      AND (status IS NULL OR status='' OR LOWER(status)='free') LIMIT 1
                """, (*update_params, f'Tunnel{tunnel_number}', f'%{tunnel_number}%', f'Tunnel{tunnel_number}%'))
                rows_updated = cursor.rowcount
                if rows_updated == 0:
                    cursor.execute("""
                        UPDATE tunnel_mali SET status='Reserved', username=?, branch_name=?,
                            reservation_date=?, interface_name=COALESCE(NULLIF(?, ''), interface_name),
                            description=COALESCE(NULLIF(?, ''), description),
                            hub_ip=COALESCE(NULLIF(?, ''), hub_ip),
                            branch_ip=COALESCE(NULLIF(?, ''), branch_ip),
                            destination_ip=COALESCE(NULLIF(?, ''), destination_ip)
                        WHERE (status IS NULL OR status='' OR LOWER(status)='free')
                        ORDER BY id LIMIT 1
                    """, update_params)
                    rows_updated = cursor.rowcount

        log_audit('reserve_tunnel_mali', f'Tunnel {tunnel_number} - {branch_name}', username, 'tunnel_mali',
                  ip_address=request.remote_addr)
        return jsonify({'status': 'ok', 'rows_updated': rows_updated})
    except Exception as e:
        return jsonify({'status': 'error', 'error': sanitize_error(e)}), 500
