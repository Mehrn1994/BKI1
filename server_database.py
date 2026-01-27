"""
Network Config Portal Server - COMPLETE FIXED VERSION
All APIs fixed + DB Manager only for Sahebdel
"""

from flask import Flask, jsonify, request, render_template
from flask_cors import CORS
import sqlite3
import os
import subprocess
import shutil
from datetime import datetime, timedelta
import json
import hashlib
import pandas as pd

app = Flask(__name__)
CORS(app)

DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'network_ipam.db')
BACKUP_DIR = os.path.join(os.path.dirname(__file__), 'data', 'backups')
ACTIVITY_LOG = os.path.join(os.path.dirname(__file__), 'data', 'activity.json')

os.makedirs(BACKUP_DIR, exist_ok=True)
os.makedirs(os.path.dirname(ACTIVITY_LOG), exist_ok=True)

ALLOWED_USERS = ["Yarian", "Sattari", "Barari", "Sahebdel", "Vahedi", "Aghajani", "Hossein", "Rezaei"]
DB_ADMIN_USER = "Sahebdel"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def init_tables():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""CREATE TABLE IF NOT EXISTS user_passwords (
        username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, created_at TEXT, last_login TEXT)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS reserved_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT, province TEXT, octet2 INTEGER, octet3 INTEGER,
        branch_name TEXT, username TEXT, reservation_date TEXT, expiry_date TEXT,
        request_number TEXT, point_type TEXT, mehregostar_code TEXT)""")
    conn.commit()
    conn.close()

init_tables()

def log_activity(atype, title, desc, user="System"):
    try:
        activities = []
        if os.path.exists(ACTIVITY_LOG):
            with open(ACTIVITY_LOG, 'r', encoding='utf-8') as f:
                activities = json.load(f)
        activities.insert(0, {'type': atype, 'title': title, 'description': desc, 'user': user, 'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')})
        activities = activities[:100]
        with open(ACTIVITY_LOG, 'w', encoding='utf-8') as f:
            json.dump(activities, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"Log error: {e}")

# ==================== PAGE ROUTES ====================
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/intranet')
def intranet_page():
    return render_template('intranet.html')

@app.route('/apn-int')
def apn_int_page():
    return render_template('apn_int.html')

@app.route('/apn-mali')
def apn_mali_page():
    return render_template('apn_mali.html')

@app.route('/reserve-lan')
def reserve_lan_page():
    return render_template('reserve_lan.html')

@app.route('/db-manager')
def db_manager_page():
    return render_template('db_manager.html')

# ==================== AUTH APIs ====================
@app.route('/api/users', methods=['GET'])
def get_users():
    conn = get_db()
    cursor = conn.cursor()
    users_info = []
    for username in ALLOWED_USERS:
        cursor.execute("SELECT username FROM user_passwords WHERE username = ?", (username,))
        users_info.append({"name": username, "registered": cursor.fetchone() is not None})
    conn.close()
    return jsonify({"users": users_info})

@app.route('/api/check-user', methods=['POST'])
def check_user():
    data = request.json
    username = data.get('username')
    if username not in ALLOWED_USERS:
        return jsonify({"error": "کاربر مجاز نیست"}), 403
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM user_passwords WHERE username = ?", (username,))
    has_password = cursor.fetchone() is not None
    conn.close()
    return jsonify({"username": username, "has_password": has_password})

@app.route('/api/register', methods=['POST'])
def register_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    if username not in ALLOWED_USERS:
        return jsonify({"error": "کاربر مجاز نیست"}), 403
    if not password or len(password) < 4:
        return jsonify({"error": "رمز باید حداقل 4 کاراکتر باشد"}), 400
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM user_passwords WHERE username = ?", (username,))
    if cursor.fetchone():
        conn.close()
        return jsonify({"error": "قبلا ثبت نام کرده"}), 400
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute("INSERT INTO user_passwords VALUES (?, ?, ?, ?)", (username, hash_password(password), now, now))
    conn.commit()
    conn.close()
    log_activity('success', 'ثبت نام', username, username)
    return jsonify({"success": True})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    if username not in ALLOWED_USERS:
        return jsonify({"success": False, "message": "کاربر مجاز نیست"}), 403
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM user_passwords WHERE username = ?", (username,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "message": "ابتدا رمز تعیین کنید", "need_register": True}), 401
    if row['password_hash'] != hash_password(password):
        conn.close()
        return jsonify({"success": False, "message": "رمز اشتباه"}), 401
    cursor.execute("UPDATE user_passwords SET last_login = ? WHERE username = ?", (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), username))
    conn.commit()
    conn.close()
    return jsonify({"success": True, "is_admin": username == DB_ADMIN_USER})

@app.route('/api/check-admin', methods=['GET'])
def check_admin():
    username = request.args.get('username', '')
    return jsonify({"is_admin": username == DB_ADMIN_USER, "admin_user": DB_ADMIN_USER})

# ==================== STATS API ====================
@app.route('/api/stats', methods=['GET'])
def get_stats():
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM lan_ips")
        total_lan = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM lan_ips WHERE username IS NULL OR username = ''")
        free_lan = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM intranet_tunnels")
        total_tun = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM intranet_tunnels WHERE LOWER(status) = 'free'")
        free_tun = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM apn_ips")
        total_apn = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM apn_ips WHERE username IS NULL OR username = ''")
        free_apn = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM apn_mali")
        total_mali = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM apn_mali WHERE username IS NULL OR username = ''")
        free_mali = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM tunnel200_ips")
        total_t200 = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM tunnel200_ips WHERE status IS NULL OR status = '' OR LOWER(status) = 'free'")
        free_t200 = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM tunnel_mali")
        total_tmali = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM tunnel_mali WHERE status IS NULL OR status = '' OR LOWER(status) = 'free'")
        free_tmali = cursor.fetchone()[0]
        
        conn.close()
        
        return jsonify({
            'lan_ips': {'total': total_lan, 'free': free_lan, 'used': total_lan - free_lan},
            'tunnels': {'total': total_tun, 'free': free_tun, 'used': total_tun - free_tun},
            'apn': {'total': total_apn, 'free': free_apn, 'used': total_apn - free_apn},
            'apn_mali': {'total': total_mali, 'free': free_mali, 'used': total_mali - free_mali},
            'tunnel200': {'total': total_t200, 'free': free_t200, 'used': total_t200 - free_t200},
            'tunnel_mali': {'total': total_tmali, 'free': free_tmali, 'used': total_tmali - free_tmali}
        })
    except Exception as e:
        print(f"❌ Stats error: {e}")
        return jsonify({'error': str(e)}), 500

# ==================== PROVINCES ====================
@app.route('/api/provinces', methods=['GET'])
def get_provinces():
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Get provinces from all tables
        provinces = set()
        
        # Garbage values to filter out
        garbage = {'SW-Roof-To-Site', 'hgfvc', '؟؟؟', 'رزرو', 'سیار', 'لوازم یدکی شاهان'}
        
        # From lan_ips (main source)
        cursor.execute("""
            SELECT DISTINCT province FROM lan_ips 
            WHERE province IS NOT NULL AND province != ''
        """)
        for row in cursor.fetchall():
            if row[0] not in garbage:
                provinces.add(row[0])
        
        # From apn_mali (for APN مالی compatibility)
        cursor.execute("""
            SELECT DISTINCT province FROM apn_mali 
            WHERE province IS NOT NULL AND province != ''
        """)
        for row in cursor.fetchall():
            if row[0] and len(row[0]) > 2 and row[0] not in garbage:
                provinces.add(row[0])
        
        # From apn_ips
        cursor.execute("""
            SELECT DISTINCT province FROM apn_ips 
            WHERE province IS NOT NULL AND province != ''
        """)
        for row in cursor.fetchall():
            if row[0] and len(row[0]) > 2 and row[0] not in garbage:
                provinces.add(row[0])
        
        conn.close()
        result = sorted(list(provinces))
        print(f"✓ Provinces: {len(result)}")
        return jsonify(result)
    except Exception as e:
        print(f"❌ Provinces error: {e}")
        return jsonify([])

# ==================== PROVINCE LOOKUP BY OCTET ====================
@app.route('/api/province-by-octet', methods=['GET'])
def get_province_by_octet():
    """Look up the correct province from lan_ips by octet2 and octet3"""
    octet2 = request.args.get('octet2')
    octet3 = request.args.get('octet3')
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT province FROM lan_ips
            WHERE octet2 = ? AND octet3 = ? AND province IS NOT NULL AND province != ''
            LIMIT 1
        """, (octet2, octet3))
        row = cursor.fetchone()
        conn.close()
        if row:
            return jsonify({'province': row['province']})
        return jsonify({'province': ''})
    except Exception as e:
        print(f"❌ Province lookup error: {e}")
        return jsonify({'province': ''})

# ==================== BRANCHES ====================
@app.route('/api/branches', methods=['GET'])
def get_branches():
    """Get branches for APN-INT - from lan_ips table (main branch source)"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, branch_name, province, octet2, octet3, wan_ip
            FROM lan_ips 
            WHERE branch_name IS NOT NULL AND branch_name != ''
            ORDER BY province, branch_name
        """)
        
        branches = []
        for row in cursor.fetchall():
            branches.append({
                'name': row['branch_name'],
                'province': row['province'] or '',
                'lan_ip': f"10.{row['octet2']}.{row['octet3']}.0/24",
                'x': row['octet2'],
                'y': row['octet3']
            })
        
        conn.close()
        print(f"✓ Branches: {len(branches)}")
        return jsonify(branches)
    except Exception as e:
        print(f"❌ Branches error: {e}")
        return jsonify([])

@app.route('/api/mali-branches', methods=['GET'])
def get_mali_branches():
    """Get branches for APN-Mali (مالی) - from apn_mali table"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, branch_name, province, lan_ip, ip_wan
            FROM apn_mali 
            WHERE branch_name IS NOT NULL AND branch_name != ''
            ORDER BY province, branch_name
        """)
        
        branches = []
        for row in cursor.fetchall():
            # Parse lan_ip to get x and y
            lan_ip = row['lan_ip'] or ''
            x, y = 0, 0
            if lan_ip:
                parts = lan_ip.replace('/24', '').split('.')
                if len(parts) >= 3:
                    try:
                        x = int(parts[1])
                        y = int(parts[2])
                    except:
                        pass
            
            branches.append({
                'name': row['branch_name'],
                'province': row['province'] or '',
                'lan_ip': lan_ip,
                'x': x,
                'y': y
            })
        
        conn.close()
        print(f"✓ Mali Branches: {len(branches)}")
        return jsonify(branches)
    except Exception as e:
        print(f"❌ Mali Branches error: {e}")
        return jsonify([])

# ==================== INTRANET TUNNELS ====================
@app.route('/tunnels', methods=['GET'])
@app.route('/api/tunnels', methods=['GET'])
def get_tunnels():
    try:
        conn = get_db()
        cursor = conn.cursor()
        # Only return FREE tunnels (status = 'Free')
        cursor.execute("""
            SELECT * FROM intranet_tunnels 
            WHERE LOWER(status) = 'free'
            ORDER BY province, tunnel_name
        """)
        
        # Map to expected field names for HTML
        tunnels = []
        for row in cursor.fetchall():
            tunnels.append({
                'IP Address': row['ip_address'],
                'Tunnel Name': row['tunnel_name'] or '',
                'IP LAN': row['ip_lan'] or '',
                'IP Intranet': row['ip_intranet'] or '',
                'Description': row['description'] or '',
                'Province': row['province'] or '',
                'Status': row['status'] or ''
            })
        
        conn.close()
        print(f"✓ Free Tunnels: {len(tunnels)}")
        return jsonify(tunnels)
    except Exception as e:
        print(f"❌ Tunnels error: {e}")
        return jsonify([])

@app.route('/reserve', methods=['POST'])
def reserve_tunnel():
    try:
        data = request.json
        ip_address = data.get('IP Address')
        username = data.get('by')
        
        conn = get_db()
        cursor = conn.cursor()
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        cursor.execute("""
            UPDATE intranet_tunnels 
            SET status = 'Reserved', reserved_by = ?, reserved_at = ?
            WHERE ip_address = ?
        """, (username, now, ip_address))
        
        conn.commit()
        conn.close()
        
        log_activity('success', 'رزرو تونل', ip_address, username)
        return jsonify({'status': 'ok'})
    except Exception as e:
        print(f"❌ Reserve tunnel error: {e}")
        return jsonify({'status': 'error', 'error': str(e)}), 500

# ==================== TUNNEL200 IPs ====================
@app.route('/api/tunnel200-ips', methods=['GET'])
def get_tunnel200_ips():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM tunnel200_ips 
            WHERE status IS NULL OR status = '' OR LOWER(status) = 'free'
            ORDER BY id
        """)
        
        ips = []
        for row in cursor.fetchall():
            ips.append({
                'id': row['id'],
                'hub_ip': row['hub_ip'],
                'branch_ip': row['branch_ip'],
                'pair': row['pair_notation'],
                'pair_notation': row['pair_notation'],
                'tunnel_number': row['tunnel_number'],
                'interface_name': row['interface_name'],
                'description': row['description'],
                'status': row['status']
            })
        
        conn.close()
        print(f"✓ Free Tunnel200 IPs: {len(ips)}")
        return jsonify(ips)
    except Exception as e:
        print(f"❌ Tunnel200 error: {e}")
        return jsonify([])

@app.route('/api/reserve-tunnel200', methods=['POST'])
def reserve_tunnel200():
    try:
        data = request.json
        hub_ip = data.get('hub_ip')
        branch_ip = data.get('branch_ip')
        username = data.get('username')
        branch_name = data.get('branch_name', '')
        tunnel_number = data.get('tunnel_number', '')
        
        conn = get_db()
        cursor = conn.cursor()
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        cursor.execute("""
            UPDATE tunnel200_ips 
            SET status = 'Reserved', username = ?, branch_name = ?, tunnel_number = ?, reservation_date = ?
            WHERE hub_ip = ? AND branch_ip = ?
        """, (username, branch_name, tunnel_number, now, hub_ip, branch_ip))
        
        conn.commit()
        conn.close()
        
        log_activity('success', 'رزرو Tunnel200', f"{hub_ip}/{branch_ip}", username)
        return jsonify({'status': 'ok'})
    except Exception as e:
        print(f"❌ Reserve tunnel200 error: {e}")
        return jsonify({'status': 'error', 'error': str(e)}), 500

# ==================== TUNNEL MALI ====================
@app.route('/api/free-tunnel-pairs', methods=['GET'])
def get_free_tunnel_pairs():
    try:
        conn = get_db()
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
            
            # Get hub_ip and branch_ip from database columns
            hub_ip = ''
            branch_ip = ''
            try:
                hub_ip = row['hub_ip'] or ''
                branch_ip = row['branch_ip'] or ''
            except:
                pass
            
            # Fallback calculation if columns don't exist
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
                'id': row['id'],
                'tunnel_number': tunnel_num,
                'tunnel_ip_hub': hub_ip,
                'tunnel_ip_branch': branch_ip,
                'interface_name': interface,
                'description': row['description'] or '',
                'ip_address': ip_addr,
                'destination_ip': row['destination_ip'] or ''
            })
        
        conn.close()
        print(f"✓ Free Tunnel Mali pairs: {len(ips)}")
        return jsonify(ips)
    except Exception as e:
        print(f"❌ Free Tunnel Pairs error: {e}")
        return jsonify([])

@app.route('/api/reserve-tunnel', methods=['POST'])
def reserve_tunnel_mali():
    try:
        data = request.json
        tunnel_id = data.get('tunnel_id') or data.get('id')
        tunnel_number = data.get('tunnel_number')
        username = data.get('username')
        branch_name = data.get('branch_name', '')
        
        conn = get_db()
        cursor = conn.cursor()
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        if tunnel_id:
            cursor.execute("""
                UPDATE tunnel_mali 
                SET status = 'Reserved', username = ?, branch_name = ?, reservation_date = ?
                WHERE id = ?
            """, (username, branch_name, now, tunnel_id))
        elif tunnel_number:
            cursor.execute("""
                UPDATE tunnel_mali 
                SET status = 'Reserved', username = ?, branch_name = ?, reservation_date = ?
                WHERE interface_name LIKE ?
            """, (username, branch_name, now, f'%{tunnel_number}%'))
        
        conn.commit()
        conn.close()
        
        log_activity('success', 'رزرو تونل مالی', f'Tunnel {tunnel_number}', username)
        return jsonify({'status': 'ok'})
    except Exception as e:
        print(f"❌ Reserve tunnel mali error: {e}")
        return jsonify({'status': 'error', 'error': str(e)}), 500

# ==================== APN IPs ====================
@app.route('/api/apn-ips', methods=['GET'])
def get_apn_ips():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM apn_ips 
            WHERE username IS NULL OR username = ''
            ORDER BY id
        """)
        
        ips = []
        for row in cursor.fetchall():
            ips.append({
                'id': row['id'],
                'ip': row['ip_wan_apn'],
                'province': row['province'],
                'branch_name': row['branch_name']
            })
        
        conn.close()
        print(f"✓ Free APN IPs: {len(ips)}")
        return jsonify(ips)
    except Exception as e:
        print(f"❌ APN IPs error: {e}")
        return jsonify([])

@app.route('/api/mali-free-ips', methods=['GET'])
def get_mali_free_ips():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM apn_mali 
            WHERE username IS NULL OR username = ''
            ORDER BY id
        """)
        
        ips = []
        for row in cursor.fetchall():
            ips.append({
                'id': row['id'],
                'ip': row['ip_wan'],
                'province': row['province'],
                'branch_name': row['branch_name']
            })
        
        conn.close()
        print(f"✓ Mali Free IPs: {len(ips)}")
        return jsonify(ips)
    except Exception as e:
        print(f"❌ Mali Free IPs error: {e}")
        return jsonify([])

# ==================== LAN IPs ====================
@app.route('/api/free-lan-ips', methods=['GET'])
def get_free_lan_ips():
    """Get free LAN IPs from lan_ips table (rows without branch name = Free IPs)"""
    province = request.args.get('province')
    
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        if province:
            cursor.execute("""
                SELECT id, branch_name, province, octet2, octet3, wan_ip, status
                FROM lan_ips 
                WHERE (branch_name IS NULL OR branch_name = '' OR status = 'Free')
                AND (username IS NULL OR username = '')
                AND province = ?
                ORDER BY octet2, octet3
            """, (province,))
        else:
            cursor.execute("""
                SELECT id, branch_name, province, octet2, octet3, wan_ip, status
                FROM lan_ips 
                WHERE (branch_name IS NULL OR branch_name = '' OR status = 'Free')
                AND (username IS NULL OR username = '')
                ORDER BY province, octet2, octet3
                LIMIT 500
            """)
        
        ips = []
        for row in cursor.fetchall():
            ips.append({
                'id': row['id'],
                'ip': f"10.{row['octet2']}.{row['octet3']}.0/24",
                'octet2': row['octet2'],
                'octet3': row['octet3'],
                'branch_name': row['branch_name'] or '',
                'province': row['province'] or '',
                'status': row['status'] or 'Free'
            })
        
        conn.close()
        print(f"✓ Free LAN IPs: {len(ips)} (province={province})")
        return jsonify(ips)
    except Exception as e:
        print(f"❌ Free LAN error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify([])
    except Exception as e:
        print(f"❌ Free LAN error: {e}")
        return jsonify([])

@app.route('/api/used-lan-ips', methods=['GET'])
def get_used_lan_ips():
    """Get active branches from lan_ips (branches with name = Active/In Use)"""
    province = request.args.get('province')
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Active branches have branch_name
        if province:
            cursor.execute("""
                SELECT id, branch_name, province, octet2, octet3, wan_ip, username, reservation_date, status
                FROM lan_ips 
                WHERE branch_name IS NOT NULL AND branch_name != ''
                AND province = ?
                ORDER BY branch_name
            """, (province,))
        else:
            cursor.execute("""
                SELECT id, branch_name, province, octet2, octet3, wan_ip, username, reservation_date, status
                FROM lan_ips 
                WHERE branch_name IS NOT NULL AND branch_name != ''
                ORDER BY province, branch_name
            """)
        
        ips = []
        for row in cursor.fetchall():
            ips.append({
                'id': row['id'],
                'ip': f"10.{row['octet2']}.{row['octet3']}.0/24",
                'octet2': row['octet2'],
                'octet3': row['octet3'],
                'branch_name': row['branch_name'] or '',
                'province': row['province'] or '',
                'username': row['username'] or '',
                'reservation_date': row['reservation_date'] or '',
                'status': row['status'] or 'Active'
            })
        
        conn.close()
        print(f"✓ Active branches: {len(ips)}")
        return jsonify(ips)
    except Exception as e:
        print(f"❌ Used LAN error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify([])

# ==================== CHECK REQUEST NUMBER ====================
@app.route('/api/check-request-number', methods=['GET'])
def check_request_number():
    request_number = request.args.get('request_number')
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM reserved_ips WHERE request_number = ?", (request_number,))
        row = cursor.fetchone()
        conn.close()
        return jsonify({'exists': row is not None, 'data': dict(row) if row else None})
    except Exception as e:
        return jsonify({'exists': False, 'error': str(e)})

# ==================== RESERVE LAN IP ====================
@app.route('/api/reserve-lan', methods=['POST'])
def reserve_lan_ip():
    try:
        data = request.json
        
        # Handle both old and new parameter names
        lan_ip = data.get('lan_ip', '')
        province = data.get('province', '')
        branch_name = data.get('point_name_persian') or data.get('branch_name', '')
        username = data.get('reserved_by') or data.get('username', '')
        request_number = data.get('request_number', '')
        point_type = data.get('point_type', '')
        mehregostar_code = data.get('mehrgestar_code') or data.get('mehregostar_code', '')
        
        # Parse lan_ip to get octet2 and octet3
        octet2 = data.get('octet2')
        octet3 = data.get('octet3')
        
        if lan_ip and not octet2:
            # Parse from lan_ip like "10.1.20.0/24"
            parts = lan_ip.replace('/24', '').split('.')
            if len(parts) >= 3:
                octet2 = int(parts[1])
                octet3 = int(parts[2])
        
        if not octet2 or not octet3 or not username:
            return jsonify({'status': 'error', 'message': 'اطلاعات ناقص است'}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        
        now = datetime.now()
        expiry = now + timedelta(days=60)
        
        # Update lan_ips table
        cursor.execute("""
            UPDATE lan_ips SET username = ?, reservation_date = ?, branch_name = ?, status = 'Reserved'
            WHERE octet2 = ? AND octet3 = ?
        """, (username, now.strftime('%Y-%m-%d'), branch_name, octet2, octet3))
        
        # Insert into reserved_ips table
        cursor.execute("""
            INSERT INTO reserved_ips (province, octet2, octet3, branch_name, username, reservation_date, expiry_date, request_number, point_type, mehregostar_code)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (province, octet2, octet3, branch_name, username, now.strftime('%Y-%m-%d'), expiry.strftime('%Y-%m-%d'), request_number, point_type, mehregostar_code))
        
        conn.commit()
        conn.close()
        
        log_activity('success', 'رزرو IP LAN', f'10.{octet2}.{octet3}.0 برای {branch_name}', username)
        return jsonify({
            'status': 'ok',
            'success': True, 
            'message': f'IP با موفقیت رزرو شد: 10.{octet2}.{octet3}.0/24',
            'ip': f'10.{octet2}.{octet3}.0/24',
            'reservation_date': now.strftime('%Y-%m-%d'), 
            'expiry_date': expiry.strftime('%Y-%m-%d')
        })
    except Exception as e:
        print(f"❌ Reserve LAN error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'status': 'error', 'success': False, 'message': str(e)}), 500

# ==================== RELEASE USED LAN ====================
@app.route('/api/release-used-lan', methods=['POST'])
def release_used_lan():
    try:
        data = request.json
        octet2 = data.get('octet2')
        octet3 = data.get('octet3')
        lan_id = data.get('id')
        
        conn = get_db()
        cursor = conn.cursor()
        
        if lan_id:
            cursor.execute("UPDATE lan_ips SET username = NULL, reservation_date = NULL WHERE id = ?", (lan_id,))
        elif octet2 and octet3:
            cursor.execute("UPDATE lan_ips SET username = NULL, reservation_date = NULL WHERE octet2 = ? AND octet3 = ?", (octet2, octet3))
        
        conn.commit()
        conn.close()
        
        log_activity('warning', 'آزادسازی IP', f'10.{octet2}.{octet3}.0')
        return jsonify({'success': True})
    except Exception as e:
        print(f"❌ Release used LAN error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ==================== RESERVED IPs ====================
@app.route('/api/reserved-ips', methods=['GET'])
def get_reserved_ips():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM reserved_ips ORDER BY reservation_date DESC")
        
        reserved = []
        for row in cursor.fetchall():
            octet2 = row['octet2']
            octet3 = row['octet3']
            reserved.append({
                'id': row['id'],
                'lan_ip': f"10.{octet2}.{octet3}.0/24",
                'province': row['province'] or '',
                'point_name_persian': row['branch_name'] or '',
                'point_type': row['point_type'] or '',
                'request_number': row['request_number'] or '',
                'reserved_by': row['username'] or '',
                'reserved_date': row['reservation_date'] or '',
                'expiry_date': row['expiry_date'] or '',
                'status': 'RESERVED',
                'octet2': octet2,
                'octet3': octet3
            })
        
        conn.close()
        return jsonify(reserved)
    except Exception as e:
        print(f"❌ Reserved IPs error: {e}")
        return jsonify([])

@app.route('/api/release-lan', methods=['POST'])
def release_lan():
    """Release a reserved LAN IP"""
    try:
        data = request.json
        lan_ip = data.get('lan_ip', '')
        
        # Parse lan_ip to get octet2 and octet3
        parts = lan_ip.replace('/24', '').split('.')
        if len(parts) < 3:
            return jsonify({'status': 'error', 'message': 'فرمت IP نامعتبر است'})
        
        octet2 = int(parts[1])
        octet3 = int(parts[2])
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Update lan_ips - clear reservation
        cursor.execute("""
            UPDATE lan_ips 
            SET username = NULL, reservation_date = NULL, status = 'Free'
            WHERE octet2 = ? AND octet3 = ?
        """, (octet2, octet3))
        
        # Delete from reserved_ips
        cursor.execute("""
            DELETE FROM reserved_ips 
            WHERE octet2 = ? AND octet3 = ?
        """, (octet2, octet3))
        
        conn.commit()
        conn.close()
        
        log_activity('success', 'آزادسازی IP', f'{lan_ip}', data.get('username', 'unknown'))
        
        return jsonify({
            'status': 'ok',
            'success': True,
            'message': f'IP {lan_ip} با موفقیت آزاد شد'
        })
    except Exception as e:
        print(f"❌ Release LAN error: {e}")
        return jsonify({'status': 'error', 'success': False, 'message': str(e)})

@app.route('/api/release-reservation', methods=['POST'])
def release_reservation():
    try:
        data = request.json
        rid = data.get('id')
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("SELECT octet2, octet3 FROM reserved_ips WHERE id = ?", (rid,))
        res = cursor.fetchone()
        
        if res:
            cursor.execute("UPDATE lan_ips SET username = NULL, reservation_date = NULL WHERE octet2 = ? AND octet3 = ?",
                           (res['octet2'], res['octet3']))
            cursor.execute("DELETE FROM reserved_ips WHERE id = ?", (rid,))
            conn.commit()
        
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ==================== RESERVE IPs ====================
@app.route('/api/reserve-ips', methods=['POST'])
def reserve_ips():
    try:
        data = request.json
        username = data.get('username')
        branch_name = data.get('branchName')
        lan_ip = data.get('lanIp')
        apn_ip = data.get('apnIp')
        
        updates = []
        conn = get_db()
        cursor = conn.cursor()
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        if lan_ip:
            parts = lan_ip.replace('/24', '').split('.')
            if len(parts) >= 3:
                octet2, octet3 = parts[1], parts[2]
                cursor.execute("""
                    UPDATE lan_ips SET username = ?, reservation_date = ?
                    WHERE octet2 = ? AND octet3 = ?
                """, (username, now, octet2, octet3))
                updates.append(f"LAN IP {lan_ip} رزرو شد")
        
        if apn_ip:
            cursor.execute("""
                UPDATE apn_ips SET username = ?, reservation_date = ?
                WHERE ip_wan_apn = ?
            """, (username, now, apn_ip))
            updates.append(f"APN IP {apn_ip} رزرو شد")
        
        conn.commit()
        conn.close()
        
        log_activity('success', 'رزرو IP', f'{branch_name}: {lan_ip}, {apn_ip}', username)
        return jsonify({'status': 'ok', 'updates': updates})
    except Exception as e:
        print(f"❌ Reserve IPs error: {e}")
        return jsonify({'status': 'error', 'error': str(e)}), 500

@app.route('/api/reserve-mali-ips', methods=['POST'])
def reserve_mali_ips():
    try:
        data = request.json
        username = data.get('username')
        branch_name = data.get('branchName')
        apn_ip = data.get('apnIp')
        tunnel_id = data.get('tunnelId')
        
        updates = []
        conn = get_db()
        cursor = conn.cursor()
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        if apn_ip:
            cursor.execute("""
                UPDATE apn_mali SET username = ?, reservation_date = ?
                WHERE ip_wan = ?
            """, (username, now, apn_ip))
            updates.append(f"APN Mali IP {apn_ip} رزرو شد")
        
        if tunnel_id:
            cursor.execute("""
                UPDATE tunnel_mali SET status = 'Reserved', username = ?, branch_name = ?, reservation_date = ?
                WHERE id = ?
            """, (username, branch_name, now, tunnel_id))
            updates.append(f"Tunnel Mali رزرو شد")
        
        conn.commit()
        conn.close()
        
        log_activity('success', 'رزرو IP مالی', f'{branch_name}: {apn_ip}', username)
        return jsonify({'status': 'ok', 'updates': updates})
    except Exception as e:
        print(f"❌ Reserve Mali IPs error: {e}")
        return jsonify({'status': 'error', 'error': str(e)}), 500

# ==================== PING ====================
@app.route('/api/ping', methods=['POST'])
def ping_ip():
    try:
        data = request.json
        ip = data.get('ip')
        result = subprocess.run(['ping', '-n', '2', '-w', '2000', ip], capture_output=True, text=True, timeout=10)
        return jsonify({'success': result.returncode == 0, 'ip': ip, 'output': result.stdout})
    except:
        return jsonify({'success': False, 'error': 'Timeout'})

@app.route('/api/ping-lan-ip', methods=['POST'])
def ping_lan_ip():
    try:
        data = request.json
        lan_ip = data.get('lan_ip', '')
        octet2 = data.get('octet2')
        octet3 = data.get('octet3')
        
        # Parse lan_ip if provided
        if lan_ip and not octet2:
            parts = lan_ip.replace('/24', '').split('.')
            if len(parts) >= 3:
                octet2 = int(parts[1])
                octet3 = int(parts[2])
        
        if not octet2 or not octet3:
            return jsonify({'reachable': False, 'message': 'پارامترها ناقص است'})
        
        # Ping format: 10.{octet2}.254.{octet3}
        ping_ip = f"10.{octet2}.254.{octet3}"
        
        # Windows ping command
        result = subprocess.run(
            ['ping', '-n', '2', '-w', '2000', ping_ip], 
            capture_output=True, 
            text=True, 
            timeout=10
        )
        
        reachable = result.returncode == 0
        
        if reachable:
            return jsonify({
                'reachable': True,
                'pinged_ip': ping_ip,
                'message': f'⚠️ IP پاسخ می‌دهد! ممکن است در استفاده باشد.'
            })
        else:
            return jsonify({
                'reachable': False,
                'pinged_ip': ping_ip,
                'message': f'✅ IP آزاد است ({ping_ip} پاسخ نداد)'
            })
    except subprocess.TimeoutExpired:
        return jsonify({
            'reachable': False,
            'pinged_ip': ping_ip if 'ping_ip' in locals() else '',
            'message': '✅ IP آزاد است (Timeout)'
        })
    except Exception as e:
        print(f"❌ Ping error: {e}")
        return jsonify({'reachable': False, 'message': f'خطا: {str(e)}'})

@app.route('/api/ping-loopback', methods=['POST'])
def ping_loopback():
    try:
        data = request.json
        
        # Accept either full IP or octet2/octet3
        loopback_ip = data.get('loopback_ip', '')
        
        if loopback_ip:
            ip = loopback_ip
        else:
            octet2 = data.get('octet2')
            octet3 = data.get('octet3')
            ip = f"10.{octet2}.254.{octet3}"
        
        # Windows ping command
        result = subprocess.run(
            ['ping', '-n', '2', '-w', '2000', ip], 
            capture_output=True, 
            text=True, 
            timeout=10
        )
        
        reachable = result.returncode == 0
        
        return jsonify({
            'success': reachable,
            'reachable': reachable,
            'ip': ip,
            'message': f'✅ {ip} پاسخ داد' if reachable else f'❌ {ip} پاسخ نداد'
        })
    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'reachable': False, 'message': 'Timeout'})
    except Exception as e:
        print(f"❌ Ping loopback error: {e}")
        return jsonify({'success': False, 'reachable': False, 'message': str(e)})

# ==================== DB MANAGEMENT ====================
@app.route('/api/db/activity', methods=['GET'])
def get_activity():
    try:
        if os.path.exists(ACTIVITY_LOG):
            with open(ACTIVITY_LOG, 'r', encoding='utf-8') as f:
                return jsonify(json.load(f))
        return jsonify([])
    except:
        return jsonify([])

@app.route('/api/db/preview-excel', methods=['POST'])
def preview_excel():
    try:
        file = request.files.get('file')
        if not file:
            return jsonify({'error': 'فایل انتخاب نشده'}), 400
        
        if file.filename.endswith('.csv'):
            df = pd.read_csv(file)
        else:
            df = pd.read_excel(file)
        
        return jsonify({
            'columns': list(df.columns), 
            'preview': df.head(20).fillna('').to_dict('records'), 
            'total_rows': len(df)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/db/import-excel', methods=['POST'])
def import_excel():
    try:
        file = request.files.get('file')
        table_name = request.form.get('table')
        username = request.form.get('username')
        
        if username != DB_ADMIN_USER:
            return jsonify({'error': 'فقط مدیر سیستم می‌تواند دیتابیس را تغییر دهد'}), 403
        
        if not file or not table_name:
            return jsonify({'error': 'فایل یا نام جدول مشخص نشده'}), 400
        
        if file.filename.endswith('.csv'):
            df = pd.read_csv(file)
        else:
            df = pd.read_excel(file)
        
        backup_name = f'backup_before_import_{datetime.now().strftime("%Y%m%d_%H%M%S")}.db'
        shutil.copy2(DB_PATH, os.path.join(BACKUP_DIR, backup_name))
        
        conn = get_db()
        df.to_sql(table_name, conn, if_exists='replace', index=False)
        conn.close()
        
        log_activity('success', 'آپلود دیتا', f'{table_name}: {len(df)} ردیف', username)
        return jsonify({'success': True, 'rows': len(df), 'backup': backup_name})
    except Exception as e:
        print(f"❌ Import Excel error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/db/backup', methods=['POST'])
def create_backup():
    try:
        fname = f'backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.db'
        shutil.copy2(DB_PATH, os.path.join(BACKUP_DIR, fname))
        log_activity('backup', 'Backup', fname)
        return jsonify({'success': True, 'filename': fname})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/db/backups', methods=['GET'])
def list_backups():
    try:
        backups = []
        if os.path.exists(BACKUP_DIR):
            for f in sorted(os.listdir(BACKUP_DIR), reverse=True):
                if f.endswith('.db'):
                    backups.append({
                        'filename': f, 
                        'size': f'{os.path.getsize(os.path.join(BACKUP_DIR, f))/1024:.1f} KB'
                    })
        return jsonify(backups)
    except:
        return jsonify([])

@app.route('/api/db/restore', methods=['POST'])
def restore_backup():
    try:
        data = request.json
        fname = data.get('filename')
        username = data.get('username')
        
        if username != DB_ADMIN_USER:
            return jsonify({'error': 'فقط مدیر سیستم می‌تواند بازیابی کند'}), 403
        
        src = os.path.join(BACKUP_DIR, fname)
        if os.path.exists(src):
            shutil.copy2(src, DB_PATH)
            log_activity('success', 'بازیابی', fname, username)
            return jsonify({'success': True})
        return jsonify({'error': 'فایل یافت نشد'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/db/reset-users', methods=['POST'])
def reset_users():
    try:
        data = request.json
        username = data.get('username')
        
        if username != DB_ADMIN_USER:
            return jsonify({'error': 'فقط مدیر سیستم می‌تواند این کار را انجام دهد'}), 403
        
        conn = get_db()
        conn.execute('DELETE FROM user_passwords')
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== MAIN ====================
if __name__ == '__main__':
    print("=" * 70)
    print("🚀 Network Config Portal - COMPLETE FIXED VERSION")
    print("=" * 70)
    print(f"📂 Database: {DB_PATH}")
    print(f"👥 Users: {', '.join(ALLOWED_USERS)}")
    print(f"🔐 DB Admin: {DB_ADMIN_USER}")
    print("=" * 70)
    app.run(host='0.0.0.0', port=5000, debug=True)
