"""Network map routes - Parse core router configs and build topology."""
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

    # Try matching province abbreviations anywhere in hostname (for core switches)
    hn_upper = hostname.upper()
    for prov_key in PROVINCE_INFO:
        pk_upper = prov_key.upper().replace('-', '')
        if len(pk_upper) >= 3 and pk_upper in hn_upper:
            return prov_key

    # Special cases for switches: SW3560X-ESF, SW3560X-KHR, etc.
    parts = hostname.replace('_', '-').split('-')
    for part in parts:
        for prov_key in PROVINCE_INFO:
            if part.upper() == prov_key.upper():
                return prov_key
            # Partial match like "Teh" for Tehran, "Maz" for Mazandaran
            if len(part) >= 3 and part.upper().startswith(prov_key.upper()[:3]):
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

    # Build links - strict hub-spoke: provincial routers connect ONLY to core routers
    node_ips = {}
    for node_info in parsed_configs.values():
        for iface in node_info['interfaces']:
            node_ips[iface['ip']] = node_info['hostname']

    core_router_set = {h for h, c in node_categories.items() if c == 'core-router'}
    core_switch_set = {h for h, c in node_categories.items() if c == 'core-switch'}
    all_core_set = core_router_set | core_switch_set
    seen_links = set()

    # Tunnel-based links: only create if one end is core-router
    for hostname, info in parsed_configs.items():
        for tunnel in info['tunnels']:
            dst = tunnel.get('tunnel_dst', '')
            if dst in node_ips:
                target = node_ips[dst]
                if hostname == target:
                    continue
                # Only create link if at least one end is a CORE ROUTER (not just switch)
                if hostname not in core_router_set and target not in core_router_set:
                    continue
                link_key = tuple(sorted([hostname, target]))
                if link_key not in seen_links:
                    seen_links.add(link_key)
                    links.append({
                        'source': hostname,
                        'target': target,
                        'type': 'tunnel',
                        'tunnel': tunnel['name'],
                        'src_ip': tunnel.get('tunnel_src', ''),
                        'dst_ip': dst,
                    })

    # Find main WAN hub routers
    hub_nodes = sorted(core_router_set)

    # Every provincial router connects to ONE core router (hub-spoke)
    if hub_nodes:
        hub = hub_nodes[0]
        for hostname, category in node_categories.items():
            if category == 'provincial-router':
                has_core_router_link = any(
                    l for l in links
                    if hostname in (l['source'], l['target'])
                    and (l['source'] in core_router_set or l['target'] in core_router_set)
                )
                if not has_core_router_link:
                    link_key = tuple(sorted([hostname, hub]))
                    if link_key not in seen_links:
                        seen_links.add(link_key)
                        links.append({
                            'source': hub,
                            'target': hostname,
                            'type': 'wan',
                            'tunnel': 'WAN',
                            'src_ip': '',
                            'dst_ip': '',
                        })

    # Core switches connect to the closest core router (or first hub)
    if hub_nodes:
        for hostname, category in node_categories.items():
            if category == 'core-switch':
                has_cr_link = any(
                    l for l in links
                    if hostname in (l['source'], l['target'])
                    and (l['source'] in core_router_set or l['target'] in core_router_set)
                )
                if not has_cr_link:
                    link_key = tuple(sorted([hostname, hub_nodes[0]]))
                    if link_key not in seen_links:
                        seen_links.add(link_key)
                        links.append({
                            'source': hub_nodes[0],
                            'target': hostname,
                            'type': 'lan',
                            'tunnel': 'LAN',
                            'src_ip': '',
                            'dst_ip': '',
                        })

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
    })
