"""Network map routes - Parse core router configs and build topology."""
import math
import os
import re
from flask import Blueprint, jsonify

from app.config import Config

network_map_bp = Blueprint('network_map', __name__)

ROUTER_DIR = os.path.join(Config.BASE_DIR, 'Router')
CORE_ROUTER_DIR = os.path.join(ROUTER_DIR, 'Core Routers')
CORE_SWITCH_DIR = os.path.join(ROUTER_DIR, 'Core Switches')

# Province abbreviation to Farsi name + Iran map coordinates
# x,y based on real geographic positions (longitude mapped to x, latitude inverted to y)
# Iran approx bounds: lon 44-63, lat 25-40 → normalized to 0-100
PROVINCE_INFO = {
    'AZSH': {'fa': 'آذربایجان شرقی', 'x': 18, 'y': 8},    # Tabriz 46.3,38.1
    'AZGH': {'fa': 'آذربایجان غربی', 'x': 10, 'y': 9},    # Urmia 45.1,37.6
    'ARD': {'fa': 'اردبیل', 'x': 24, 'y': 5},              # Ardabil 48.3,38.3
    'ESF': {'fa': 'اصفهان', 'x': 42, 'y': 50},             # Isfahan 51.7,32.7
    'ALZ': {'fa': 'البرز', 'x': 40, 'y': 22},              # Karaj 50.9,35.8
    'ILM': {'fa': 'ایلام', 'x': 16, 'y': 48},              # Ilam 46.4,33.6
    'BSH': {'fa': 'بوشهر', 'x': 40, 'y': 72},              # Bushehr 50.8,28.9
    'M1-Tehran': {'fa': 'تهران ۱', 'x': 42, 'y': 24},      # Tehran center
    'M2-Tehran': {'fa': 'تهران ۲', 'x': 43, 'y': 25},      # Tehran
    'OSTehran': {'fa': 'استان تهران', 'x': 41, 'y': 23},   # Tehran
    'KHRJ': {'fa': 'خراسان جنوبی', 'x': 74, 'y': 48},      # Birjand 59.2,32.9
    'KHR': {'fa': 'خراسان رضوی', 'x': 76, 'y': 28},        # Mashhad 59.6,36.3
    'KhShomali': {'fa': 'خراسان شمالی', 'x': 70, 'y': 18},  # Bojnurd 57.3,37.5
    'KHZ': {'fa': 'خوزستان', 'x': 26, 'y': 58},            # Ahvaz 48.7,31.3
    'ZNJ': {'fa': 'زنجان', 'x': 24, 'y': 18},              # Zanjan 48.5,36.7
    'SMN': {'fa': 'سمنان', 'x': 50, 'y': 24},              # Semnan 53.4,35.6
    'SNB': {'fa': 'سیستان و بلوچستان', 'x': 90, 'y': 72},  # Zahedan 60.9,29.5
    'FRS': {'fa': 'فارس', 'x': 48, 'y': 68},               # Shiraz 52.5,29.6
    'QZV': {'fa': 'قزوین', 'x': 36, 'y': 20},              # Qazvin 50.0,36.3
    'QOM': {'fa': 'قم', 'x': 40, 'y': 32},                 # Qom 50.9,34.6
    'LOR': {'fa': 'لرستان', 'x': 24, 'y': 44},             # Khorramabad 48.4,33.5
    'MAZ': {'fa': 'مازندران', 'x': 46, 'y': 14},           # Sari 53.1,36.6
    'MRZ': {'fa': 'مرکزی', 'x': 36, 'y': 36},              # Arak 49.7,34.1
    'HMZ': {'fa': 'هرمزگان', 'x': 58, 'y': 82},            # Bandar Abbas 56.3,27.2
    'HMD': {'fa': 'همدان', 'x': 26, 'y': 34},              # Hamadan 48.5,34.8
    'CHB': {'fa': 'چهارمحال و بختیاری', 'x': 38, 'y': 52},  # Shahrekord 50.9,32.3
    'KRD': {'fa': 'کردستان', 'x': 16, 'y': 30},            # Sanandaj 47.0,35.3
    'KRM': {'fa': 'کرمان', 'x': 66, 'y': 62},              # Kerman 57.1,30.3
    'KRMJ': {'fa': 'کرمانشاه', 'x': 14, 'y': 38},          # Kermanshah 47.1,34.3
    'KNB': {'fa': 'کهگیلویه و بویراحمد', 'x': 38, 'y': 60}, # Yasuj 51.6,30.7
    'GLS': {'fa': 'گلستان', 'x': 56, 'y': 12},             # Gorgan 54.4,36.8
    'GIL': {'fa': 'گیلان', 'x': 34, 'y': 10},              # Rasht 49.6,37.3
    'YZD': {'fa': 'یزد', 'x': 56, 'y': 52},                # Yazd 54.4,31.9
    'KRSH': {'fa': 'کرمانشاه', 'x': 14, 'y': 38},          # Kermanshah alias
}

# Aliases for province abbreviation matching (switch hostnames use different formats)
PROVINCE_ALIASES = {
    'KHSH': 'KhShomali',   # SW3560X-KHSH → Khorasan Shomali
    'Teh': 'OSTehran',     # SW3560X-TehB, SW3650X-TEH → Tehran
    'TehB': 'OSTehran',
    'TEH': 'OSTehran',
    'Maz': 'MAZ',          # SW3560X-Maz → Mazandaran
    'AzGh': 'AZGH',        # SW3850-AzGh → Azerbaijan Gharbi
    'Babolsar': 'MAZ',     # Core-SW-Babolsar → Mazandaran
    'CENTERII': 'OSTehran', # 3750-1-CENTERII → Tehran data center
    'Tehran': 'OSTehran',  # MO-SH-Tehran-CORESW → Tehran
}


def _parse_config(filepath):
    """Parse a Cisco IOS config file and extract key info."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception:
        return None

    info = {
        'hostname': '',
        'model': '',
        'interfaces': [],
        'tunnels': [],
        'nat_rules': [],
        'ospf_processes': [],
        'static_routes': [],
        'crypto_maps': [],
        'acls': [],
    }

    # Hostname
    m = re.search(r'^hostname\s+(.+)', content, re.MULTILINE)
    if m:
        info['hostname'] = m.group(1).strip()

    # Model from version or boot
    m = re.search(r'(ASR\d+|C\d{4}|ISR\d+|\d{4})', info['hostname'])
    if m:
        info['model'] = m.group(1)

    # Interfaces with IPs
    for m in re.finditer(r'^interface\s+(\S+)\s*\n((?:.*\n)*?)(?=^interface\s|\Z)', content, re.MULTILINE):
        iface_name = m.group(1)
        iface_block = m.group(2)
        ips = re.findall(r'ip address\s+(\S+)\s+(\S+)', iface_block)
        desc = re.search(r'description\s+(.+)', iface_block)
        nat_line = re.search(r'ip nat\s+(inside|outside)', iface_block)
        if ips:
            for ip, mask in ips:
                entry = {'name': iface_name, 'ip': ip, 'mask': mask}
                if desc:
                    entry['description'] = desc.group(1).strip()
                if nat_line:
                    entry['nat'] = nat_line.group(1)
                if 'Tunnel' in iface_name:
                    src = re.search(r'tunnel source\s+(\S+)', iface_block)
                    dst = re.search(r'tunnel destination\s+(\S+)', iface_block)
                    if src:
                        entry['tunnel_src'] = src.group(1)
                    if dst:
                        entry['tunnel_dst'] = dst.group(1)
                    info['tunnels'].append(entry)
                else:
                    info['interfaces'].append(entry)

    # NAT rules - parse structured
    nat_interfaces = []
    for m in re.finditer(r'^ip nat (inside|outside)\s+source\s+(.+)', content, re.MULTILINE):
        rule_text = m.group(2).strip()
        rule = {'type': 'dynamic', 'direction': m.group(1)}
        if 'static' in rule_text:
            rule['type'] = 'static'
            parts = rule_text.split()
            if len(parts) >= 2:
                rule['inside_ip'] = parts[1] if len(parts) > 1 else ''
                rule['outside_ip'] = parts[2] if len(parts) > 2 else ''
        else:
            acl_m = re.search(r'list\s+(\S+)', rule_text)
            pool_m = re.search(r'pool\s+(\S+)', rule_text)
            iface_m = re.search(r'interface\s+(\S+)', rule_text)
            if acl_m:
                rule['acl'] = acl_m.group(1)
            if pool_m:
                rule['pool'] = pool_m.group(1)
            if iface_m:
                rule['interface'] = iface_m.group(1)
            rule['overload'] = 'overload' in rule_text
        info['nat_rules'].append(rule)

    # NAT pool definitions
    for m in re.finditer(r'^ip nat pool\s+(\S+)\s+(\S+)\s+(\S+)', content, re.MULTILINE):
        info['nat_rules'].append({
            'type': 'pool', 'name': m.group(1),
            'start': m.group(2), 'end': m.group(3)
        })

    # OSPF
    for m in re.finditer(r'^router ospf\s+(\d+)\s*\n((?:.*\n)*?)(?=^router\s|^\!)', content, re.MULTILINE):
        ospf_block = m.group(2)
        networks = re.findall(r'network\s+(\S+)\s+(\S+)\s+area\s+(\S+)', ospf_block)
        router_id_m = re.search(r'router-id\s+(\S+)', ospf_block)
        redistribute = re.findall(r'redistribute\s+(.+)', ospf_block)
        info['ospf_processes'].append({
            'process': m.group(1),
            'router_id': router_id_m.group(1) if router_id_m else '',
            'networks': [{'net': n, 'wildcard': w, 'area': a} for n, w, a in networks],
            'redistribute': [r.strip() for r in redistribute]
        })

    # Static routes
    routes = []
    for m in re.finditer(r'^ip route\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+name\s+(\S+))?', content, re.MULTILINE):
        routes.append({
            'dest': m.group(1), 'mask': m.group(2),
            'next_hop': m.group(3), 'name': m.group(4) or ''
        })
    info['static_routes'] = routes[:30]

    # Crypto maps
    for m in re.finditer(r'^crypto map\s+(\S+)\s+(\d+)', content, re.MULTILINE):
        info['crypto_maps'].append({'name': m.group(1), 'seq': m.group(2)})

    # Access lists
    acl_dict = {}
    for m in re.finditer(r'^access-list\s+(\S+)\s+(permit|deny)\s+(.+)', content, re.MULTILINE):
        acl_name = m.group(1)
        if acl_name not in acl_dict:
            acl_dict[acl_name] = []
        acl_dict[acl_name].append({'action': m.group(2), 'rule': m.group(3).strip()})
    info['acls'] = acl_dict

    return info


def _abbr_from_hostname(hostname):
    """Extract province abbreviation from hostname."""
    parts = hostname.split('-')
    if len(parts) >= 2:
        abbr = parts[1]
        if len(parts) >= 3 and abbr in ('M1', 'M2', 'OS', 'Mo'):
            abbr = '-'.join(parts[1:3])
        return abbr
    return hostname


def _extract_province_from_name(hostname):
    """Try to extract province abbreviation from any hostname format."""
    # First try standard format
    abbr = _abbr_from_hostname(hostname)
    if abbr in PROVINCE_INFO:
        return abbr

    # Check aliases for the abbreviation
    if abbr in PROVINCE_ALIASES:
        return PROVINCE_ALIASES[abbr]

    # Try matching aliases in any part of hostname
    parts = hostname.replace('_', '-').split('-')
    for part in parts:
        if part in PROVINCE_ALIASES:
            return PROVINCE_ALIASES[part]
        # Case-insensitive alias check
        for alias_key, alias_val in PROVINCE_ALIASES.items():
            if part.upper() == alias_key.upper():
                return alias_val

    # Try matching province abbreviations anywhere in hostname (for core switches)
    hn_upper = hostname.upper()
    for prov_key in PROVINCE_INFO:
        pk_upper = prov_key.upper().replace('-', '')
        if len(pk_upper) >= 3 and pk_upper in hn_upper:
            return prov_key

    # Special cases for switches: SW3560X-ESF, SW3560X-KHR, etc.
    for part in parts:
        for prov_key in PROVINCE_INFO:
            if part.upper() == prov_key.upper():
                return prov_key
            # Partial match like "Teh" for Tehran, "Maz" for Mazandaran
            if len(part) >= 3 and len(prov_key) >= 3 and part.upper().startswith(prov_key.upper()[:3]):
                return prov_key

    return None


def _classify_device(hostname, source_dir):
    """Classify a device based on its source directory and hostname."""
    if source_dir == 'core-router':
        return 'core-router'
    if source_dir == 'core-switch':
        return 'core-switch'
    return 'provincial-router'


def _scan_directory(dirpath, category):
    """Scan a directory for config files and return parsed results."""
    results = []
    if not os.path.exists(dirpath):
        return results
    for fname in sorted(os.listdir(dirpath)):
        fpath = os.path.join(dirpath, fname)
        if not os.path.isfile(fpath) or os.path.getsize(fpath) < 100:
            continue
        info = _parse_config(fpath)
        if info and info['hostname']:
            results.append((info, category, fname))
    return results


def _parse_nat_full(filepath):
    """Deep parse of a single router config for complete NAT flow data."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception:
        return None

    result = {
        'hostname': '',
        'inside_interfaces': [],   # {name, ip, mask, description}
        'outside_interfaces': [],  # {name, ip, mask, description}
        'nat_rules': [],           # {type, acl, pool, overload_intf, inside_ip, outside_ip, overload}
        'nat_pools': [],           # {name, start_ip, end_ip, netmask, prefix}
        'acl_content': {},         # {acl_name: [{action, network, wildcard, description}]}
    }

    m = re.search(r'^hostname\s+(.+)', content, re.MULTILINE)
    if m:
        result['hostname'] = m.group(1).strip()

    # ── Parse all interface blocks ──────────────────────────────────────────
    iface_pattern = re.compile(
        r'^interface\s+(\S+)(.*?)(?=^interface\s|\Z)',
        re.MULTILINE | re.DOTALL
    )
    for im in iface_pattern.finditer(content):
        iface_name = im.group(1)
        block = im.group(2)

        nat_side = re.search(r'ip nat\s+(inside|outside)', block)
        if not nat_side:
            continue

        ip_m = re.search(r'ip address\s+(\S+)\s+(\S+)', block)
        desc_m = re.search(r'description\s+(.+)', block)

        entry = {
            'name': iface_name,
            'ip': ip_m.group(1) if ip_m else '',
            'mask': ip_m.group(2) if ip_m else '',
            'description': desc_m.group(1).strip().strip('"') if desc_m else '',
        }
        side = nat_side.group(1)
        if side == 'inside':
            result['inside_interfaces'].append(entry)
        else:
            result['outside_interfaces'].append(entry)

    # ── Parse NAT rules ─────────────────────────────────────────────────────
    for nm in re.finditer(r'^ip nat\s+(?:inside|outside)\s+source\s+(.+)', content, re.MULTILINE):
        rule_text = nm.group(1).strip()
        if 'static' in rule_text:
            parts = rule_text.split()
            # static tcp/udp port forwarding or simple static
            rule = {'type': 'static'}
            idx = 1  # skip 'static'
            if parts[0] == 'static' and len(parts) >= 3:
                # ip nat inside source static <inside_ip> <outside_ip>
                # ip nat inside source static tcp <inside_ip> <port> <outside_ip> <port>
                if parts[idx] in ('tcp', 'udp'):
                    rule['protocol'] = parts[idx]
                    rule['inside_ip'] = parts[idx + 1] if len(parts) > idx + 1 else ''
                    rule['inside_port'] = parts[idx + 2] if len(parts) > idx + 2 else ''
                    rule['outside_ip'] = parts[idx + 3] if len(parts) > idx + 3 else ''
                    rule['outside_port'] = parts[idx + 4] if len(parts) > idx + 4 else ''
                else:
                    rule['inside_ip'] = parts[idx] if len(parts) > idx else ''
                    rule['outside_ip'] = parts[idx + 1] if len(parts) > idx + 1 else ''
        else:
            rule = {'type': 'dynamic'}
            acl_m = re.search(r'list\s+(\S+)', rule_text)
            pool_m = re.search(r'pool\s+(\S+)', rule_text)
            iface_m = re.search(r'interface\s+(\S+)', rule_text)
            rule['acl'] = acl_m.group(1) if acl_m else ''
            rule['pool'] = pool_m.group(1) if pool_m else ''
            rule['overload_intf'] = iface_m.group(1) if iface_m else ''
            rule['overload'] = 'overload' in rule_text
            rule['pat'] = rule['overload']

        result['nat_rules'].append(rule)

    # ── Parse NAT pools ─────────────────────────────────────────────────────
    for pm in re.finditer(
        r'^ip nat pool\s+(\S+)\s+(\S+)\s+(\S+)\s+(?:netmask\s+(\S+)|prefix-length\s+(\S+))',
        content, re.MULTILINE
    ):
        result['nat_pools'].append({
            'name': pm.group(1),
            'start_ip': pm.group(2),
            'end_ip': pm.group(3),
            'netmask': pm.group(4) or '',
            'prefix': pm.group(5) or '',
        })

    # ── Parse extended and standard ACLs ────────────────────────────────────
    # Extended ACLs: "ip access-list extended <name>"
    ext_acl_pattern = re.compile(
        r'^ip access-list extended\s+(\S+)\s*\n(.*?)(?=^ip access-list\s|^router\s|^!\s*\n!\s*\n|^ip nat\s|\Z)',
        re.MULTILINE | re.DOTALL
    )
    for am in ext_acl_pattern.finditer(content):
        acl_name = am.group(1)
        acl_block = am.group(2)
        entries = []
        for em in re.finditer(
            r'^\s*(permit|deny)\s+(ip|tcp|udp|icmp|any)\s+(\S+)(?:\s+(\S+))?(?:\s+(\S+))?(?:\s+(\S+))?',
            acl_block, re.MULTILINE
        ):
            entries.append({
                'action': em.group(1),
                'proto': em.group(2),
                'src': em.group(3),
                'src_wild': em.group(4) or '',
                'dst': em.group(5) or '',
                'dst_wild': em.group(6) or '',
            })
        if entries:
            result['acl_content'][acl_name] = entries

    # Standard ACLs: "ip access-list standard <name>"
    std_acl_pattern = re.compile(
        r'^ip access-list standard\s+(\S+)\s*\n(.*?)(?=^ip access-list\s|^router\s|^!\s*\n!\s*\n|\Z)',
        re.MULTILINE | re.DOTALL
    )
    for am in std_acl_pattern.finditer(content):
        acl_name = am.group(1)
        acl_block = am.group(2)
        entries = []
        for em in re.finditer(
            r'^\s*(permit|deny)\s+(\S+)(?:\s+(\S+))?',
            acl_block, re.MULTILINE
        ):
            src = em.group(2)
            if src in ('any', 'host'):
                src = f"{src} {em.group(3) or ''}".strip()
            entries.append({
                'action': em.group(1),
                'proto': 'ip',
                'src': src,
                'src_wild': em.group(3) or '' if em.group(2) not in ('any', 'host') else '',
                'dst': 'any',
                'dst_wild': '',
            })
        if entries:
            result['acl_content'][acl_name] = entries

    # Numbered ACLs: "access-list <num> permit/deny ..."
    for am in re.finditer(r'^access-list\s+(\S+)\s+(permit|deny)\s+(.+)', content, re.MULTILINE):
        acl_name = am.group(1)
        rule_parts = am.group(3).strip().split()
        if acl_name not in result['acl_content']:
            result['acl_content'][acl_name] = []
        result['acl_content'][acl_name].append({
            'action': am.group(2),
            'proto': 'ip',
            'src': rule_parts[0] if rule_parts else '',
            'src_wild': rule_parts[1] if len(rule_parts) > 1 else '',
            'dst': rule_parts[2] if len(rule_parts) > 2 else 'any',
            'dst_wild': rule_parts[3] if len(rule_parts) > 3 else '',
        })

    return result


def _scan_all_router_dirs():
    """Scan all router directories (flat + subdirs) and return (filepath, fname, category) tuples."""
    results = []
    # Provincial routers (top-level files only)
    if os.path.exists(ROUTER_DIR):
        for fname in sorted(os.listdir(ROUTER_DIR)):
            fpath = os.path.join(ROUTER_DIR, fname)
            if os.path.isfile(fpath) and os.path.getsize(fpath) >= 100:
                results.append((fpath, fname, 'provincial-router'))
    # Core Routers
    if os.path.exists(CORE_ROUTER_DIR):
        for fname in sorted(os.listdir(CORE_ROUTER_DIR)):
            fpath = os.path.join(CORE_ROUTER_DIR, fname)
            if os.path.isfile(fpath) and os.path.getsize(fpath) >= 100:
                results.append((fpath, fname, 'core-router'))
    # Core Switches
    if os.path.exists(CORE_SWITCH_DIR):
        for fname in sorted(os.listdir(CORE_SWITCH_DIR)):
            fpath = os.path.join(CORE_SWITCH_DIR, fname)
            if os.path.isfile(fpath) and os.path.getsize(fpath) >= 100:
                results.append((fpath, fname, 'core-switch'))
    return results


@network_map_bp.route('/api/network-map/nat-diagram', methods=['GET'])
def get_nat_diagram():
    """Parse all router/switch configs and return full NAT flow data for visualization."""
    devices = []
    all_files = _scan_all_router_dirs()

    for filepath, fname, category in all_files:
        data = _parse_nat_full(filepath)
        if not data:
            continue
        # Only include devices that have NAT configured
        if not data['nat_rules']:
            continue

        # Enrich each NAT rule with its ACL source networks
        for rule in data['nat_rules']:
            if rule.get('type') == 'dynamic' and rule.get('acl'):
                acl_name = rule['acl']
                rule['acl_entries'] = data['acl_content'].get(acl_name, [])
                # Get overload interface IP
                ov_intf = rule.get('overload_intf', '')
                rule['overload_ip'] = ''
                if ov_intf:
                    for oi in data['outside_interfaces']:
                        if oi['name'] == ov_intf:
                            rule['overload_ip'] = oi['ip']
                            break

        # Get province info for label
        abbr = _abbr_from_hostname(data['hostname'])
        pinfo = PROVINCE_INFO.get(abbr, {})

        devices.append({
            'hostname': data['hostname'],
            'label': pinfo.get('fa', data['hostname']),
            'abbr': abbr,
            'category': category,
            'source_file': fname,
            'inside_interfaces': data['inside_interfaces'],
            'outside_interfaces': data['outside_interfaces'],
            'nat_rules': data['nat_rules'],
            'nat_pools': data['nat_pools'],
        })

    # Sort: core first, then provincial, then switches
    order = {'core-router': 0, 'provincial-router': 1, 'core-switch': 2}
    devices.sort(key=lambda d: (order.get(d['category'], 3), d['hostname']))

    return jsonify({
        'devices': devices,
        'total': len(devices),
        'total_rules': sum(len(d['nat_rules']) for d in devices),
    })


@network_map_bp.route('/api/network-map/topology', methods=['GET'])
def get_topology():
    """Parse all router configs and return topology data."""
    nodes = []
    links = []

    if not os.path.exists(ROUTER_DIR):
        return jsonify({'nodes': [], 'links': [], 'error': 'Router directory not found'})

    # Scan all three directories
    all_configs = []
    # Provincial routers (top-level Router/ directory files only)
    all_configs.extend(_scan_directory(ROUTER_DIR, 'provincial-router'))
    # Core routers
    all_configs.extend(_scan_directory(CORE_ROUTER_DIR, 'core-router'))
    # Core switches
    all_configs.extend(_scan_directory(CORE_SWITCH_DIR, 'core-switch'))

    parsed_configs = {}
    node_categories = {}

    for info, category, fname in all_configs:
        hostname = info['hostname']
        abbr = _abbr_from_hostname(hostname)
        pinfo = PROVINCE_INFO.get(abbr, {})

        # For core switches, try harder to find province
        if not pinfo and category == 'core-switch':
            prov = _extract_province_from_name(hostname)
            if prov:
                abbr = prov
                pinfo = PROVINCE_INFO.get(abbr, {})

        # Position based on category
        if category == 'core-router':
            cx, cy = 42, 24  # Tehran center
        elif category == 'core-switch':
            cx = pinfo.get('x', 42)
            cy = pinfo.get('y', 24)
        else:
            cx = pinfo.get('x', 50)
            cy = pinfo.get('y', 50)

        # Get NAT interface info
        nat_interfaces = []
        for iface in info['interfaces']:
            if iface.get('nat'):
                nat_interfaces.append({'name': iface['name'], 'side': iface['nat']})
        for tunnel in info['tunnels']:
            if tunnel.get('nat'):
                nat_interfaces.append({'name': tunnel['name'], 'side': tunnel['nat']})

        node = {
            'id': hostname,
            'abbr': abbr,
            'label': pinfo.get('fa', hostname),
            'x': cx,
            'y': cy,
            'model': info['model'] or fname.split('-')[0],
            'category': category,
            'interfaces_count': len(info['interfaces']),
            'tunnels_count': len(info['tunnels']),
            'nat_count': len(info['nat_rules']),
            'ospf_count': len(info['ospf_processes']),
            'static_routes_count': len(info['static_routes']),
            'acl_count': len(info['acls']),
            'interfaces': info['interfaces'][:15],
            'tunnels': info['tunnels'][:15],
            'nat_rules': info['nat_rules'][:20],
            'nat_interfaces': nat_interfaces,
            'ospf': info['ospf_processes'],
            'static_routes': info['static_routes'],
            'access_lists': info['acls'],
            'crypto_maps': [c['name'] for c in info['crypto_maps']],
        }
        nodes.append(node)
        parsed_configs[hostname] = info
        node_categories[hostname] = category

    # ── Position core routers ABOVE the map (separate Data Center zone) ──
    # This prevents accidental clicks on core routers when targeting provincials.
    # Provincial routers are at y >= 5, core routers will be at y < 0.
    WAN_HUB_NAMES = ['ASR1006-WAN-MB', 'WAN-INTR1', 'WAN-INTR2']
    core_nodes = [n for n in nodes if n['category'] == 'core-router']
    wan_hubs = [n for n in core_nodes if n['id'] in WAN_HUB_NAMES]
    other_cores = [n for n in core_nodes if n['id'] not in WAN_HUB_NAMES]

    # WAN hubs: prominent row at top
    hub_positions = [
        ('ASR1006-WAN-MB', 42, -28),
        ('WAN-INTR1', 30, -28),
        ('WAN-INTR2', 54, -28),
    ]
    for name, hx, hy in hub_positions:
        for n in wan_hubs:
            if n['id'] == name:
                n['x'], n['y'] = hx, hy

    # Other core routers: two rows below WAN hubs, wide spread
    if other_cores:
        half = (len(other_cores) + 1) // 2
        spacing = 6
        for idx, n in enumerate(other_cores):
            if idx < half:
                row_count = half
                row_y = -19
                i = idx
            else:
                row_count = len(other_cores) - half
                row_y = -12
                i = idx - half
            total_w = (row_count - 1) * spacing
            n['x'] = round(42 - total_w / 2 + i * spacing, 1)
            n['y'] = row_y

    # ── Build IP → hostname lookup for tunnel-based link detection ──
    ip_to_hostname = {}
    for hostname, info in parsed_configs.items():
        for iface in info['interfaces']:
            if iface.get('ip') and iface['ip'] != 'negotiated':
                ip_to_hostname[iface['ip']] = hostname
        for tunnel in info['tunnels']:
            if tunnel.get('ip') and tunnel['ip'] != 'negotiated':
                ip_to_hostname[tunnel['ip']] = hostname
            # Also map tunnel source IPs
            if tunnel.get('tunnel_src') and not tunnel['tunnel_src'].startswith(('Loopback', 'GigabitEthernet', 'FastEthernet')):
                ip_to_hostname[tunnel['tunnel_src']] = hostname

    core_router_set = {h for h, c in node_categories.items() if c == 'core-router'}
    seen_links = set()

    def add_link(src, tgt, link_type, label, src_ip='', dst_ip=''):
        lk = tuple(sorted([src, tgt]))
        if lk not in seen_links and src != tgt:
            seen_links.add(lk)
            links.append({
                'source': src, 'target': tgt,
                'type': link_type, 'tunnel': label,
                'src_ip': src_ip, 'dst_ip': dst_ip,
            })

    def _classify_tunnel_link(tunnel_name, tunnel_ip, src_hostname, dst_hostname):
        """Classify tunnel link type based on name, IP ranges, and endpoints."""
        tname_lower = tunnel_name.lower()
        # APN tunnels typically have specific naming or IP patterns
        if 'apn' in tname_lower:
            return 'apn'
        # Check tunnel IP to classify
        if tunnel_ip:
            parts = tunnel_ip.split('.')
            if len(parts) == 4:
                first = int(parts[0]) if parts[0].isdigit() else 0
                second = int(parts[1]) if parts[1].isdigit() else 0
                # 172.16.x.x - typically MPLS/VPLS tunnels
                if first == 172 and 16 <= second <= 31:
                    return 'mpls'
                # 10.200.x.x or Tunnel200+ - typically APN
                if first == 10 and second == 200:
                    return 'apn'
                # 10.100.x.x - typically WAN tunnels
                if first == 10 and second == 100:
                    return 'wan'
        # Tunnel number heuristic
        tnum_m = re.search(r'Tunnel(\d+)', tunnel_name)
        if tnum_m:
            tnum = int(tnum_m.group(1))
            if tnum >= 200:
                return 'apn'
            if tnum >= 100:
                return 'mpls'
        # If both are core routers → backbone
        if src_hostname in core_router_set and dst_hostname in core_router_set:
            return 'backbone'
        return 'wan'

    # Find WAN hubs
    wan_hub_ids = [n['id'] for n in wan_hubs]
    if not wan_hub_ids:
        wan_hub_ids = sorted(core_router_set)[:1]
    primary_hub = wan_hub_ids[0] if wan_hub_ids else None

    # ═══════════════════════════════════════════════════
    # STEP 1: Tunnel-based links (real connectivity from configs)
    # ═══════════════════════════════════════════════════
    tunnel_connected = set()  # Track which nodes have tunnel-based links
    for hostname, info in parsed_configs.items():
        for tunnel in info['tunnels']:
            dst_ip = tunnel.get('tunnel_dst', '')
            if not dst_ip:
                continue
            # Find which router owns this destination IP
            dst_hostname = ip_to_hostname.get(dst_ip)
            if dst_hostname and dst_hostname != hostname:
                link_type = _classify_tunnel_link(
                    tunnel.get('name', ''), tunnel.get('ip', ''),
                    hostname, dst_hostname
                )
                add_link(hostname, dst_hostname, link_type,
                         tunnel.get('name', 'Tunnel'),
                         tunnel.get('ip', ''), dst_ip)
                tunnel_connected.add(hostname)
                tunnel_connected.add(dst_hostname)

    # ═══════════════════════════════════════════════════
    # STEP 2: Fallback WAN links for provincials without tunnel links
    # ═══════════════════════════════════════════════════
    provincial_list = sorted(
        [h for h, c in node_categories.items() if c == 'provincial-router']
    )
    for i, hostname in enumerate(provincial_list):
        if hostname not in tunnel_connected:
            # No tunnel links found - add fallback WAN link to hub
            hub = wan_hub_ids[i % len(wan_hub_ids)] if wan_hub_ids else None
            if hub:
                add_link(hub, hostname, 'wan', 'WAN')

    # ═══════════════════════════════════════════════════
    # STEP 3: Core switches → province router (LAN)
    # ═══════════════════════════════════════════════════
    prov_to_router = {}
    for hostname, category in node_categories.items():
        if category == 'provincial-router':
            abbr = _abbr_from_hostname(hostname)
            if abbr and abbr in PROVINCE_INFO:
                prov_to_router[abbr] = hostname
            # Also check aliases
            resolved = PROVINCE_ALIASES.get(abbr)
            if resolved and resolved in PROVINCE_INFO:
                prov_to_router[resolved] = hostname

    for hostname, category in node_categories.items():
        if category == 'core-switch':
            if hostname not in tunnel_connected:
                prov = _extract_province_from_name(hostname)
                matched_router = prov_to_router.get(prov) if prov else None
                if matched_router:
                    add_link(matched_router, hostname, 'lan', 'LAN')
                elif primary_hub:
                    add_link(primary_hub, hostname, 'lan', 'LAN')

    # ═══════════════════════════════════════════════════
    # STEP 4: Core routers → primary WAN hub (if no tunnel links)
    # ═══════════════════════════════════════════════════
    if primary_hub:
        for hostname in sorted(core_router_set):
            if hostname not in wan_hub_ids and hostname not in tunnel_connected:
                add_link(primary_hub, hostname, 'core', 'Core')

    # ═══════════════════════════════════════════════════
    # STEP 5: WAN hubs interconnect (backbone)
    # ═══════════════════════════════════════════════════
    for i in range(len(wan_hub_ids)):
        for j in range(i + 1, len(wan_hub_ids)):
            add_link(wan_hub_ids[i], wan_hub_ids[j], 'backbone', 'WAN Backbone')

    # ═══════════════════════════════════════════════════
    # STEP 6: Ensure every node has at least one link
    # ═══════════════════════════════════════════════════
    linked_nodes = set()
    for l in links:
        linked_nodes.add(l['source'])
        linked_nodes.add(l['target'])
    for n in nodes:
        if n['id'] not in linked_nodes and primary_hub:
            cat = node_categories.get(n['id'], '')
            lt = 'core' if cat == 'core-router' else 'lan' if cat == 'core-switch' else 'wan'
            add_link(primary_hub, n['id'], lt, lt.upper())

    # Count link types
    link_type_counts = {}
    for l in links:
        lt = l['type']
        link_type_counts[lt] = link_type_counts.get(lt, 0) + 1

    core_count = sum(1 for n in nodes if n['category'] == 'core-router')
    switch_count = sum(1 for n in nodes if n['category'] == 'core-switch')
    provincial_count = sum(1 for n in nodes if n['category'] == 'provincial-router')

    return jsonify({
        'nodes': nodes,
        'links': links,
        'total_routers': len(nodes),
        'total_links': len(links),
        'core_count': core_count,
        'switch_count': switch_count,
        'provincial_count': provincial_count,
        'link_types': link_type_counts,
        '_version': 'v7-tunnel-accurate',
    })
