"""
Network Topology Auto-Sync - Daily SSH polling of all devices (READ-ONLY).

SSHs into each configured device, runs show commands, saves updated config
to Router/ directory, detects changes, and logs them to the database.
NEVER modifies device configuration - only runs 'show' commands.
"""
import os
import re
import time
import base64
import hashlib
import shutil
import threading
from datetime import datetime

from app.config import Config
from app.database import get_db

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

ROUTER_DIR = os.path.join(Config.BASE_DIR, 'Router')

# Read-only commands - NEVER modify device config
READONLY_COMMANDS = [
    'show running-config',
    'show ip route',
    'show ip interface brief',
    'show ip ospf neighbor',
]

_sync_lock = threading.Lock()
_sync_running = False


class NetworkSyncError(Exception):
    pass


# ─── Obfuscation (not crypto-secure, internal use only) ─────────────────────

def _get_key() -> str:
    return hashlib.md5(Config.SECRET_KEY.encode()).hexdigest()[:16]


def obfuscate_password(plaintext: str) -> str:
    """XOR + base64 obfuscation for device passwords stored in DB."""
    key = _get_key()
    key_bytes = (key * (len(plaintext) // len(key) + 1)).encode()[:len(plaintext)]
    xored = bytes(a ^ b for a, b in zip(plaintext.encode(), key_bytes))
    return base64.b64encode(xored).decode()


def deobfuscate_password(encoded: str) -> str:
    """Reverse obfuscation."""
    try:
        key = _get_key()
        data = base64.b64decode(encoded)
        key_bytes = (key * (len(data) // len(key) + 1)).encode()[:len(data)]
        return bytes(a ^ b for a, b in zip(data, key_bytes)).decode()
    except Exception:
        return ''


# ─── SSH Engine ──────────────────────────────────────────────────────────────

def _ssh_fetch_config(host: str, username: str, password: str,
                      timeout: int = 30) -> str:
    """
    SSH to a Cisco IOS device and fetch 'show running-config' output.
    Returns raw config string. Raises NetworkSyncError on failure.
    READ-ONLY: only runs show commands.
    """
    if not PARAMIKO_AVAILABLE:
        raise NetworkSyncError("paramiko not installed - run: pip install paramiko")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            host, port=22, username=username, password=password,
            timeout=timeout, look_for_keys=False, allow_agent=False,
            banner_timeout=20,
        )
    except Exception as e:
        raise NetworkSyncError(f"SSH connect failed to {host}: {e}")

    try:
        shell = client.invoke_shell(term='vt100', width=250, height=50)
        time.sleep(1.5)

        # Clear banner
        _flush(shell)

        # Disable pager (read-only terminal command)
        shell.send('terminal length 0\n')
        time.sleep(0.8)
        _flush(shell)

        # Fetch running config
        shell.send('show running-config\n')
        raw = _read_until_prompt(shell, timeout=60)

        shell.close()
        return raw

    except NetworkSyncError:
        raise
    except Exception as e:
        raise NetworkSyncError(f"SSH session error: {e}")
    finally:
        client.close()


def _flush(shell) -> str:
    buf = ''
    time.sleep(0.3)
    while shell.recv_ready():
        buf += shell.recv(65535).decode('utf-8', errors='ignore')
        time.sleep(0.1)
    return buf


def _read_until_prompt(shell, timeout: int = 60) -> str:
    """Read shell output until Cisco IOS prompt (hostname#) appears."""
    output = ''
    deadline = time.time() + timeout
    while time.time() < deadline:
        if shell.recv_ready():
            chunk = shell.recv(65535).decode('utf-8', errors='ignore')
            output += chunk
            # IOS prompt ends with '#' or '>' after the command finishes
            stripped = output.rstrip()
            if stripped.endswith('#') or stripped.endswith('>'):
                time.sleep(0.2)
                if shell.recv_ready():
                    output += shell.recv(65535).decode('utf-8', errors='ignore')
                break
        else:
            time.sleep(0.3)
    return output


# ─── Config Parsing ──────────────────────────────────────────────────────────

def _parse_config(content: str) -> dict:
    """Parse Cisco IOS running-config into structured dict for comparison."""
    data = {
        'hostname': '',
        'interfaces': [],
        'tunnels': [],
        'nat_rules': [],
        'static_routes': [],
        'ospf_networks': [],
    }

    m = re.search(r'^hostname\s+(.+)', content, re.MULTILINE)
    if m:
        data['hostname'] = m.group(1).strip()

    # Interfaces and tunnels
    for m in re.finditer(
        r'^interface\s+(\S+)\s*\n((?:.*\n)*?)(?=^interface\s|\Z)',
        content, re.MULTILINE
    ):
        iface_name = m.group(1)
        block = m.group(2)
        ips = re.findall(r'ip address\s+(\S+)\s+(\S+)', block)
        desc = re.search(r'description\s+(.+)', block)
        shutdown = bool(re.search(r'^\s*shutdown', block, re.MULTILINE))

        for ip, mask in ips:
            entry = {
                'name': iface_name,
                'ip': ip,
                'mask': mask,
                'description': desc.group(1).strip() if desc else '',
                'shutdown': shutdown,
            }
            if 'Tunnel' in iface_name:
                src = re.search(r'tunnel source\s+(\S+)', block)
                dst = re.search(r'tunnel destination\s+(\S+)', block)
                entry['tunnel_src'] = src.group(1) if src else ''
                entry['tunnel_dst'] = dst.group(1) if dst else ''
                data['tunnels'].append(entry)
            else:
                data['interfaces'].append(entry)

    # Static routes
    for m in re.finditer(
        r'^ip route\s+(\S+)\s+(\S+)\s+(\S+)', content, re.MULTILINE
    ):
        data['static_routes'].append({
            'network': m.group(1),
            'mask': m.group(2),
            'nexthop': m.group(3),
        })

    # NAT rules (summary)
    for m in re.finditer(
        r'^ip nat\s+\S+\s+source\s+(.+)', content, re.MULTILINE
    ):
        data['nat_rules'].append(m.group(1).strip())

    # OSPF networks
    for m in re.finditer(
        r'^\s+network\s+(\S+)\s+(\S+)\s+area\s+(\S+)',
        content, re.MULTILINE
    ):
        data['ospf_networks'].append(f"{m.group(1)}/{m.group(2)} area {m.group(3)}")

    return data


# ─── Change Detection ─────────────────────────────────────────────────────────

def _detect_changes(old: dict, new: dict, hostname: str) -> list:
    """Compare two parsed configs and return a list of change records."""
    changes = []
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def chg(ctype, detail, old_v='', new_v='', severity='info'):
        changes.append({
            'detected_at': now,
            'hostname': hostname,
            'change_type': ctype,
            'change_detail': detail,
            'old_value': str(old_v),
            'new_value': str(new_v),
            'severity': severity,
        })

    # Interfaces
    old_ifaces = {f"{i['name']}:{i['ip']}": i for i in old.get('interfaces', [])}
    new_ifaces = {f"{i['name']}:{i['ip']}": i for i in new.get('interfaces', [])}

    for k in set(old_ifaces) - set(new_ifaces):
        i = old_ifaces[k]
        chg('interface_removed',
            f"Interface {i['name']} IP {i['ip']}/{i['mask']} removed",
            old_v=f"{i['ip']}/{i['mask']}", severity='warning')

    for k in set(new_ifaces) - set(old_ifaces):
        i = new_ifaces[k]
        chg('interface_added',
            f"Interface {i['name']} IP {i['ip']}/{i['mask']} added",
            new_v=f"{i['ip']}/{i['mask']}")

    # Tunnels
    old_tun = {t['name']: t for t in old.get('tunnels', [])}
    new_tun = {t['name']: t for t in new.get('tunnels', [])}

    for name in set(old_tun) - set(new_tun):
        t = old_tun[name]
        chg('tunnel_removed',
            f"Tunnel {name} removed (src:{t.get('tunnel_src','')} → dst:{t.get('tunnel_dst','')})",
            old_v=f"src={t.get('tunnel_src','')} dst={t.get('tunnel_dst','')}", severity='warning')

    for name in set(new_tun) - set(old_tun):
        t = new_tun[name]
        chg('tunnel_added',
            f"Tunnel {name} added (src:{t.get('tunnel_src','')} → dst:{t.get('tunnel_dst','')})",
            new_v=f"src={t.get('tunnel_src','')} dst={t.get('tunnel_dst','')}")

    for name in set(old_tun) & set(new_tun):
        old_dst = old_tun[name].get('tunnel_dst', '')
        new_dst = new_tun[name].get('tunnel_dst', '')
        if old_dst != new_dst:
            chg('tunnel_changed',
                f"Tunnel {name} destination changed",
                old_v=old_dst, new_v=new_dst, severity='warning')

    # Static routes
    old_routes = {
        f"{r['network']}/{r['mask']}->{r['nexthop']}"
        for r in old.get('static_routes', [])
    }
    new_routes = {
        f"{r['network']}/{r['mask']}->{r['nexthop']}"
        for r in new.get('static_routes', [])
    }

    for route in old_routes - new_routes:
        chg('route_removed', f"Static route removed: {route}",
            old_v=route, severity='warning')

    for route in new_routes - old_routes:
        chg('route_added', f"Static route added: {route}", new_v=route)

    # NAT rules
    old_nat = set(old.get('nat_rules', []))
    new_nat = set(new.get('nat_rules', []))

    for rule in old_nat - new_nat:
        chg('nat_removed', f"NAT rule removed: {rule}", old_v=rule, severity='warning')
    for rule in new_nat - old_nat:
        chg('nat_added', f"NAT rule added: {rule}", new_v=rule)

    # OSPF networks
    old_ospf = set(old.get('ospf_networks', []))
    new_ospf = set(new.get('ospf_networks', []))

    for net in old_ospf - new_ospf:
        chg('ospf_removed', f"OSPF network removed: {net}", old_v=net, severity='warning')
    for net in new_ospf - old_ospf:
        chg('ospf_added', f"OSPF network added: {net}", new_v=net)

    return changes


# ─── File Management ──────────────────────────────────────────────────────────

def _find_config_file(hostname: str, router_file: str = '') -> str:
    """Locate the existing config file for a device."""
    # Try explicit router_file first
    if router_file:
        for base in [ROUTER_DIR,
                     os.path.join(ROUTER_DIR, 'Core Routers'),
                     os.path.join(ROUTER_DIR, 'Core Switches')]:
            p = os.path.join(base, router_file)
            if os.path.exists(p):
                return p

    # Walk Router/ and search by hostname
    for root, _, files in os.walk(ROUTER_DIR):
        for fname in files:
            if hostname.lower() in fname.lower():
                return os.path.join(root, fname)

    return ''


def _save_config(hostname: str, content: str, router_file: str = '') -> str:
    """Save new config to file, keeping .bak of old. Returns saved path."""
    path = _find_config_file(hostname, router_file)

    if not path:
        # New device - create file in Router/
        path = os.path.join(ROUTER_DIR, hostname)

    # Backup old
    if os.path.exists(path):
        try:
            shutil.copy2(path, path + '.bak')
        except Exception:
            pass

    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)

    return path


# ─── DB Operations ────────────────────────────────────────────────────────────

def _store_changes(changes: list):
    if not changes:
        return
    conn = get_db()
    try:
        for c in changes:
            conn.execute(
                """INSERT INTO topology_changes
                   (detected_at, hostname, change_type, change_detail,
                    old_value, new_value, severity)
                   VALUES (?,?,?,?,?,?,?)""",
                (c['detected_at'], c['hostname'], c['change_type'],
                 c['change_detail'], c['old_value'], c['new_value'], c['severity'])
            )
        conn.commit()
    finally:
        conn.close()


def _update_device_status(device_id: int, status: str):
    conn = get_db()
    try:
        conn.execute(
            "UPDATE network_devices SET last_sync=?, last_sync_status=? WHERE id=?",
            (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), status, device_id)
        )
        conn.commit()
    finally:
        conn.close()


def _create_sync_log(started_at: str) -> int:
    conn = get_db()
    try:
        cur = conn.execute(
            """INSERT INTO sync_log (started_at, status,
               devices_total, devices_success, devices_failed, changes_detected)
               VALUES (?, 'running', 0, 0, 0, 0)""",
            (started_at,)
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def _finish_sync_log(log_id: int, total: int, success: int, fail: int, changes: int):
    conn = get_db()
    try:
        conn.execute(
            """UPDATE sync_log SET status='completed', completed_at=?,
               devices_total=?, devices_success=?, devices_failed=?,
               changes_detected=? WHERE id=?""",
            (datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
             total, success, fail, changes, log_id)
        )
        conn.commit()
    finally:
        conn.close()


# ─── Per-device Sync ──────────────────────────────────────────────────────────

def sync_device(device: dict) -> dict:
    """
    SSH to one device (read-only), compare config, save changes.
    Returns {'success': bool, 'hostname': str, 'changes': list, 'error': str}
    """
    hostname = device['hostname']
    ip = device['ip_address']
    username = device['username']
    password = deobfuscate_password(device['password_enc'])
    router_file = device.get('router_file') or ''

    result = {'success': False, 'hostname': hostname, 'changes': [], 'error': ''}

    try:
        # Fetch config via SSH (read-only)
        raw = _ssh_fetch_config(ip, username, password)

        if not raw or len(raw.strip()) < 50:
            result['error'] = 'Empty or invalid config received'
            return result

        # Parse new config
        new_data = _parse_config(raw)

        # Parse existing file for comparison
        old_data = {'interfaces': [], 'tunnels': [], 'nat_rules': [],
                    'static_routes': [], 'ospf_networks': []}
        old_file = _find_config_file(hostname, router_file)
        if old_file:
            try:
                with open(old_file, 'r', encoding='utf-8', errors='ignore') as f:
                    old_data = _parse_config(f.read())
            except Exception:
                pass

        # Detect and store changes
        changes = _detect_changes(old_data, new_data, hostname)
        _store_changes(changes)

        # Save updated config file
        _save_config(hostname, raw, router_file)

        result['success'] = True
        result['changes'] = changes

    except NetworkSyncError as e:
        result['error'] = str(e)
    except Exception as e:
        result['error'] = f"Unexpected error: {e}"

    return result


# ─── Full Sync ────────────────────────────────────────────────────────────────

def run_full_sync() -> dict:
    """
    Sync all enabled devices. Called by daily background task or manual trigger.
    Returns summary dict.
    """
    global _sync_running

    with _sync_lock:
        if _sync_running:
            return {'success': False, 'message': 'Sync already running'}
        _sync_running = True

    started_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_id = _create_sync_log(started_at)

    try:
        conn = get_db()
        try:
            rows = conn.execute(
                "SELECT * FROM network_devices WHERE enabled=1 ORDER BY hostname"
            ).fetchall()
            devices = [dict(r) for r in rows]
        finally:
            conn.close()

        if not devices:
            _finish_sync_log(log_id, 0, 0, 0, 0)
            return {'success': True, 'total': 0, 'log_id': log_id,
                    'message': 'No devices configured'}

        total = len(devices)
        success_count = fail_count = total_changes = 0

        for device in devices:
            print(f"[NetworkSync] {device['hostname']} ({device['ip_address']}) ...", flush=True)
            result = sync_device(device)

            n_changes = len(result['changes'])
            total_changes += n_changes

            if result['success']:
                success_count += 1
                print(f"[NetworkSync]   OK — {n_changes} change(s)", flush=True)
            else:
                fail_count += 1
                print(f"[NetworkSync]   FAILED: {result['error']}", flush=True)

            _update_device_status(
                device['id'],
                'success' if result['success'] else 'failed'
            )

        _finish_sync_log(log_id, total, success_count, fail_count, total_changes)

        return {
            'success': True,
            'log_id': log_id,
            'total': total,
            'success_count': success_count,
            'fail_count': fail_count,
            'changes': total_changes,
        }

    finally:
        with _sync_lock:
            _sync_running = False


def is_sync_running() -> bool:
    return _sync_running
