"""Tools routes - Ping, search, PDF report."""
import re
import platform
import subprocess
import time
from datetime import datetime
from flask import Blueprint, jsonify, request, Response

from app.database import get_db_readonly, log_audit
from app.security import validate_host, sanitize_output, sanitize_error

tools_bp = Blueprint('tools', __name__)


@tools_bp.route('/api/ping', methods=['POST'])
def ping_host():
    data = request.json or {}
    if not data.get('host'):
        return jsonify({'error': 'Host is required'}), 400
    host = data['host'].strip()
    if not validate_host(host):
        return jsonify({'error': 'Invalid host format'}), 400
    try:
        count_flag = '-n' if platform.system().lower() == 'windows' else '-c'
        timeout_flag = '-w' if platform.system().lower() == 'windows' else '-W'
        timeout_val = '3000' if platform.system().lower() == 'windows' else '3'
        result = subprocess.run(
            ['ping', count_flag, '3', timeout_flag, timeout_val, host],
            capture_output=True, text=True, timeout=15
        )
        output = result.stdout + result.stderr
        reachable = result.returncode == 0
        avg_ms = None
        if reachable:
            avg_match = re.search(r'Average\s*=\s*(\d+)', output)
            if not avg_match:
                avg_match = re.search(r'avg[^=]*=\s*[\d.]+/([\d.]+)', output)
            if avg_match:
                avg_ms = float(avg_match.group(1))
        return jsonify({'reachable': reachable, 'host': host, 'avg_ms': avg_ms, 'output': output.strip()})
    except subprocess.TimeoutExpired:
        return jsonify({'reachable': False, 'host': host, 'avg_ms': None, 'output': 'Ping timed out'})
    except Exception:
        return jsonify({'reachable': False, 'host': host, 'avg_ms': None, 'output': 'Ping failed'})


@tools_bp.route('/api/ping-lan-ip', methods=['POST'])
def ping_lan_ip():
    try:
        data = request.json or {}
        lan_ip = data.get('lan_ip', '')
        octet2 = data.get('octet2')
        octet3 = data.get('octet3')
        if lan_ip and not octet2:
            parts = lan_ip.replace('/24', '').split('.')
            if len(parts) >= 3:
                octet2, octet3 = int(parts[1]), int(parts[2])
        if not octet2 or not octet3:
            return jsonify({'reachable': False, 'message': 'Invalid parameters'})
        ping_ip = f"10.{octet2}.254.{octet3}"
        if platform.system().lower() == 'windows':
            cmd = ['ping', '-n', '2', '-w', '2000', ping_ip]
        else:
            cmd = ['ping', '-c', '2', '-W', '2', ping_ip]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        reachable = result.returncode == 0
        msg = f'IP responds - may be in use' if reachable else f'IP is free ({ping_ip} no response)'
        return jsonify({'reachable': reachable, 'pinged_ip': ping_ip, 'message': msg})
    except subprocess.TimeoutExpired:
        return jsonify({'reachable': False, 'pinged_ip': ping_ip if 'ping_ip' in dir() else '', 'message': 'IP is free (Timeout)'})
    except Exception:
        return jsonify({'reachable': False, 'message': 'Ping failed'})


@tools_bp.route('/api/ping-loopback', methods=['POST'])
def ping_loopback():
    try:
        data = request.json or {}
        loopback_ip = data.get('loopback_ip', '')
        if loopback_ip:
            ip = loopback_ip
        else:
            ip = f"10.{data.get('octet2')}.254.{data.get('octet3')}"

        if not validate_host(ip):
            return jsonify({'success': False, 'message': 'Invalid IP'}), 400

        if platform.system().lower() == 'windows':
            cmd = ['ping', '-n', '2', '-w', '2000', ip]
        else:
            cmd = ['ping', '-c', '2', '-W', '2', ip]
        start_time = time.time()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        response_time = (time.time() - start_time) * 1000 / 2
        reachable = result.returncode == 0
        return jsonify({
            'success': reachable, 'reachable': reachable, 'ip': ip,
            'responseTime': round(response_time, 2) if reachable else None,
            'message': f'{ip} responded' if reachable else f'{ip} no response'
        })
    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'reachable': False, 'message': 'Timeout'})
    except Exception:
        return jsonify({'success': False, 'reachable': False, 'message': 'Ping failed'})


@tools_bp.route('/api/search', methods=['GET'])
def smart_search():
    q = request.args.get('q', '').strip()
    if not q or len(q) < 2:
        return jsonify([])
    results = []
    like = f'%{q}%'

    with get_db_readonly() as conn:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT 'lan_ip' as type, branch_name, province, octet2, octet3, username, status
            FROM lan_ips WHERE branch_name LIKE ? OR province LIKE ? OR username LIKE ?
            OR (octet2||'.'||octet3) LIKE ? LIMIT 15
        """, (like, like, like, like))
        for r in cursor.fetchall():
            results.append({
                'type': 'lan_ip', 'icon': 'pin',
                'title': f"10.{r['octet2']}.{r['octet3']}.0/24",
                'subtitle': f"{sanitize_output(r['province'])} - {sanitize_output(r['branch_name'] or 'Free')}",
                'extra': sanitize_output(r['username'] or ''), 'status': r['status'] or 'Free',
                'link': '/reserve-lan'
            })

        cursor.execute("""
            SELECT 'tunnel' as type, tunnel_name, ip_address, description, province, status
            FROM intranet_tunnels WHERE tunnel_name LIKE ? OR ip_address LIKE ? OR description LIKE ? OR province LIKE ? LIMIT 10
        """, (like, like, like, like))
        for r in cursor.fetchall():
            results.append({
                'type': 'tunnel', 'icon': 'link',
                'title': sanitize_output(r['tunnel_name'] or r['ip_address']),
                'subtitle': sanitize_output(r['description'] or r['province'] or ''),
                'extra': r['ip_address'] or '', 'status': r['status'] or 'Free',
                'link': '/intranet'
            })

        cursor.execute("""
            SELECT 'apn' as type, branch_name, province, lan_ip, ip_wan_apn, username
            FROM apn_ips WHERE branch_name LIKE ? OR province LIKE ? OR lan_ip LIKE ? OR ip_wan_apn LIKE ? LIMIT 10
        """, (like, like, like, like))
        for r in cursor.fetchall():
            results.append({
                'type': 'apn_int', 'icon': 'apn',
                'title': sanitize_output(r['ip_wan_apn'] or r['lan_ip'] or ''),
                'subtitle': f"{sanitize_output(r['province'])} - {sanitize_output(r['branch_name'] or '')}",
                'extra': sanitize_output(r['username'] or 'Free'),
                'status': 'Used' if r['username'] else 'Free', 'link': '/apn-int'
            })

        cursor.execute("""
            SELECT 'apn_mali' as type, branch_name, province, lan_ip, ip_wan, username
            FROM apn_mali WHERE branch_name LIKE ? OR province LIKE ? OR lan_ip LIKE ? OR ip_wan LIKE ? LIMIT 10
        """, (like, like, like, like))
        for r in cursor.fetchall():
            results.append({
                'type': 'apn_mali', 'icon': 'apn',
                'title': sanitize_output(r['ip_wan'] or r['lan_ip'] or ''),
                'subtitle': f"{sanitize_output(r['province'])} - {sanitize_output(r['branch_name'] or '')}",
                'extra': sanitize_output(r['username'] or 'Free'),
                'status': 'Used' if r['username'] else 'Free', 'link': '/apn-mali'
            })

        try:
            cursor.execute("""
                SELECT COALESCE(branch_name, branch_name_en) as bname, province, interface_name, lan_ip
                FROM ptmp_connections WHERE branch_name LIKE ? OR branch_name_en LIKE ? OR interface_name LIKE ? OR province LIKE ? LIMIT 10
            """, (like, like, like, like))
            for r in cursor.fetchall():
                results.append({
                    'type': 'ptmp', 'icon': 'serial',
                    'title': sanitize_output(r['bname'] or r['interface_name'] or ''),
                    'subtitle': f"{sanitize_output(r['province'] or '')} - {sanitize_output(r['interface_name'] or '')}",
                    'extra': r['lan_ip'] or '', 'status': 'Used', 'link': '/service-management'
                })
        except Exception:
            pass

    return jsonify(results[:30])


@tools_bp.route('/api/report/pdf', methods=['GET'])
def generate_pdf_report():
    try:
        with get_db_readonly() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT
                    (SELECT COUNT(*) FROM lan_ips) as total_lan,
                    (SELECT COUNT(*) FROM lan_ips WHERE (username IS NULL OR username='') AND (branch_name IS NULL OR branch_name='')) as free_lan,
                    (SELECT COUNT(*) FROM intranet_tunnels) as total_tun,
                    (SELECT COUNT(*) FROM intranet_tunnels WHERE LOWER(status)='free') as free_tun,
                    (SELECT COUNT(*) FROM apn_ips) as total_apn,
                    (SELECT COUNT(*) FROM apn_ips WHERE username IS NULL OR username='') as free_apn,
                    (SELECT COUNT(*) FROM apn_mali) as total_mali,
                    (SELECT COUNT(*) FROM apn_mali WHERE username IS NULL OR username='') as free_mali,
                    (SELECT COUNT(*) FROM reserved_ips WHERE status='reserved') as active_res,
                    (SELECT COUNT(*) FROM ptmp_connections) as total_ptmp,
                    (SELECT COUNT(*) FROM ptmp_connections WHERE branch_name IS NOT NULL) as matched_ptmp
            """)
            s = cursor.fetchone()

            cursor.execute("""
                SELECT province, COUNT(*) as cnt FROM lan_ips
                WHERE province IS NOT NULL AND province!='' AND username IS NOT NULL AND username!=''
                GROUP BY province ORDER BY cnt DESC LIMIT 10
            """)
            top_provinces = [{'province': r['province'], 'count': r['cnt']} for r in cursor.fetchall()]

            cursor.execute("""
                SELECT province, branch_name, octet2, octet3, username, reservation_date, status
                FROM reserved_ips ORDER BY reservation_date DESC LIMIT 15
            """)
            recent_res = [dict(r) for r in cursor.fetchall()]

            cursor.execute("""
                SELECT province, branch_name, octet2, octet3, expiry_date, username
                FROM reserved_ips WHERE status='reserved' AND expiry_date <= date('now', '+7 days')
                ORDER BY expiry_date ASC LIMIT 10
            """)
            expiring = [dict(r) for r in cursor.fetchall()]

        now = datetime.now().strftime('%Y-%m-%d %H:%M')
        username = sanitize_output(request.args.get('user', 'System'))

        html = f"""<!DOCTYPE html>
<html lang="fa" dir="rtl"><head><meta charset="UTF-8">
<title>Network Status Report - {now}</title>
<style>
@page {{ size: A4; margin: 15mm; }}
* {{ margin:0; padding:0; box-sizing:border-box; font-family:'Segoe UI',Tahoma,sans-serif; }}
body {{ padding:20px; color:#1e293b; font-size:12px; direction:rtl; }}
.header {{ text-align:center; border-bottom:3px solid #1e40af; padding-bottom:15px; margin-bottom:20px; }}
.header h1 {{ color:#1e40af; font-size:20px; }} .header p {{ color:#64748b; font-size:11px; }}
.stats-grid {{ display:grid; grid-template-columns:repeat(5,1fr); gap:12px; margin-bottom:20px; }}
.stat-box {{ background:#f1f5f9; border:1px solid #e2e8f0; border-radius:8px; padding:12px; text-align:center; }}
.stat-box .val {{ font-size:22px; font-weight:700; color:#1e40af; }}
.stat-box .lbl {{ font-size:10px; color:#64748b; }}
.stat-box .sub {{ display:flex; justify-content:center; gap:12px; margin-top:6px; font-size:10px; }}
.free {{ color:#059669; }} .used {{ color:#dc2626; }}
.section {{ margin-bottom:18px; }} .section h2 {{ font-size:14px; color:#1e40af; border-bottom:2px solid #e2e8f0; padding-bottom:6px; margin-bottom:10px; }}
table {{ width:100%; border-collapse:collapse; font-size:11px; }}
th {{ background:#1e40af; color:white; padding:6px 8px; text-align:right; }}
td {{ padding:5px 8px; border-bottom:1px solid #e2e8f0; }}
tr:nth-child(even) {{ background:#f8fafc; }}
.footer {{ text-align:center; color:#94a3b8; font-size:10px; margin-top:20px; border-top:1px solid #e2e8f0; padding-top:10px; }}
.alert {{ background:#fef2f2; border:1px solid #fecaca; border-radius:6px; padding:8px 12px; margin-bottom:12px; color:#dc2626; font-size:11px; }}
</style></head><body>
<div class="header"><h1>Network Status Report - Keshavarzi Bank</h1>
<p>Date: {now} | By: {username}</p></div>
<div class="stats-grid">
<div class="stat-box"><div class="val">{s['total_lan']}</div><div class="lbl">LAN IPs</div><div class="sub"><span class="free">Free: {s['free_lan']}</span><span class="used">Used: {s['total_lan']-s['free_lan']}</span></div></div>
<div class="stat-box"><div class="val">{s['total_tun']}</div><div class="lbl">Intranet</div><div class="sub"><span class="free">Free: {s['free_tun']}</span><span class="used">Used: {s['total_tun']-s['free_tun']}</span></div></div>
<div class="stat-box"><div class="val">{s['total_apn']}</div><div class="lbl">APN INT</div><div class="sub"><span class="free">Free: {s['free_apn']}</span><span class="used">Used: {s['total_apn']-s['free_apn']}</span></div></div>
<div class="stat-box"><div class="val">{s['total_mali']}</div><div class="lbl">APN Mali</div><div class="sub"><span class="free">Free: {s['free_mali']}</span><span class="used">Used: {s['total_mali']-s['free_mali']}</span></div></div>
<div class="stat-box"><div class="val">{s['total_ptmp']}</div><div class="lbl">PTMP</div><div class="sub"><span class="used">Total: {s['total_ptmp']}</span><span class="free">Matched: {s['matched_ptmp']}</span></div></div>
</div>"""

        if expiring:
            html += f'<div class="alert">{len(expiring)} reservations expiring in 7 days</div>'

        # Top provinces
        html += '<div class="section"><h2>Top Provinces</h2><table><tr><th>Province</th><th>Count</th><th>Bar</th></tr>'
        max_c = top_provinces[0]['count'] if top_provinces else 1
        for p in top_provinces:
            pct = int((p['count'] / max_c) * 100)
            html += f'<tr><td>{sanitize_output(p["province"])}</td><td>{p["count"]}</td><td><div style="width:{pct}%;height:14px;background:linear-gradient(90deg,#3b82f6,#1e40af);border-radius:3px"></div></td></tr>'
        html += '</table></div>'

        # Recent reservations
        html += '<div class="section"><h2>Recent Reservations</h2><table><tr><th>IP</th><th>Province</th><th>Branch</th><th>User</th><th>Date</th><th>Status</th></tr>'
        for r in recent_res:
            ip = f"10.{r['octet2']}.{r['octet3']}.0/24"
            html += f"<tr><td>{ip}</td><td>{sanitize_output(r['province'] or '')}</td><td>{sanitize_output(r['branch_name'] or '')}</td><td>{sanitize_output(r['username'] or '')}</td><td>{r['reservation_date'] or ''}</td><td>{r['status'] or ''}</td></tr>"
        html += '</table></div>'

        html += f'<div class="footer">Network Configuration Portal - {now}</div></body></html>'

        log_audit('pdf_report', 'PDF report generated', username, 'report', ip_address=request.remote_addr)
        return Response(html, mimetype='text/html')
    except Exception as e:
        return jsonify({'error': sanitize_error(e)}), 500
