"""Network map routes - Parse core router configs and build topology."""
import os
import re
from flask import Blueprint, jsonify

from app.config import Config

network_map_bp = Blueprint('network_map', __name__)

ROUTER_DIR = os.path.join(Config.BASE_DIR, 'Router')
CORE_ROUTER_DIR = os.path.join(ROUTER_DIR, 'Core Routers')
CORE_SWITCH_DIR = os.path.join(ROUTER_DIR, 'Core Switches')

# Province abbreviation to Farsi name + approximate lat/lng for Iran map (normalized 0-100)
PROVINCE_INFO = {
    'AZSH': {'fa': 'آذربایجان شرقی', 'x': 28, 'y': 12},
    'AZGH': {'fa': 'آذربایجان غربی', 'x': 20, 'y': 12},
    'ARD': {'fa': 'اردبیل', 'x': 32, 'y': 8},
    'ESF': {'fa': 'اصفهان', 'x': 48, 'y': 50},
    'ALZ': {'fa': 'البرز', 'x': 42, 'y': 28},
    'ILM': {'fa': 'ایلام', 'x': 25, 'y': 45},
    'BSH': {'fa': 'بوشهر', 'x': 44, 'y': 70},
    'M1-Tehran': {'fa': 'تهران ۱', 'x': 44, 'y': 30},
    'M2-Tehran': {'fa': 'تهران ۲', 'x': 46, 'y': 30},
    'OSTehran': {'fa': 'استان تهران', 'x': 44, 'y': 32},
    'KHRJ': {'fa': 'خراسان جنوبی', 'x': 72, 'y': 50},
    'KHR': {'fa': 'خراسان رضوی', 'x': 72, 'y': 35},
    'KhShomali': {'fa': 'خراسان شمالی', 'x': 70, 'y': 25},
    'KHZ': {'fa': 'خوزستان', 'x': 34, 'y': 55},
    'ZNJ': {'fa': 'زنجان', 'x': 32, 'y': 22},
    'SMN': {'fa': 'سمنان', 'x': 55, 'y': 28},
    'SNB': {'fa': 'سیستان و بلوچستان', 'x': 82, 'y': 65},
    'FRS': {'fa': 'فارس', 'x': 48, 'y': 65},
    'QZV': {'fa': 'قزوین', 'x': 38, 'y': 25},
    'QOM': {'fa': 'قم', 'x': 44, 'y': 35},
    'LOR': {'fa': 'لرستان', 'x': 32, 'y': 42},
    'MAZ': {'fa': 'مازندران', 'x': 48, 'y': 20},
    'MRZ': {'fa': 'مرکزی', 'x': 40, 'y': 38},
    'HMZ': {'fa': 'هرمزگان', 'x': 55, 'y': 78},
    'HMD': {'fa': 'همدان', 'x': 34, 'y': 35},
    'CHB': {'fa': 'چهارمحال و بختیاری', 'x': 42, 'y': 50},
    'KRD': {'fa': 'کردستان', 'x': 26, 'y': 30},
    'KRM': {'fa': 'کرمان', 'x': 62, 'y': 60},
    'KRMJ': {'fa': 'کرمانشاه', 'x': 26, 'y': 38},
    'KNB': {'fa': 'کهگیلویه و بویراحمد', 'x': 42, 'y': 58},
    'GLS': {'fa': 'گلستان', 'x': 58, 'y': 18},
    'GIL': {'fa': 'گیلان', 'x': 38, 'y': 16},
    'YZD': {'fa': 'یزد', 'x': 56, 'y': 52},
    'KRSH': {'fa': 'کرمانشاه', 'x': 26, 'y': 38},
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

        # For core devices, position them in the center (Tehran area)
        if category == 'core-router':
            cx, cy = 45, 30
        elif category == 'core-switch':
            # Place switches near their province if identifiable, else near center
            cx = pinfo.get('x', 45)
            cy = pinfo.get('y', 32)
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

    # Build links from tunnel destinations
    # Only allow links where at least one end is a core device
    node_ips = {}
    for node_info in parsed_configs.values():
        for iface in node_info['interfaces']:
            node_ips[iface['ip']] = node_info['hostname']

    core_set = {h for h, c in node_categories.items() if c in ('core-router', 'core-switch')}
    seen_links = set()

    for hostname, info in parsed_configs.items():
        for tunnel in info['tunnels']:
            dst = tunnel.get('tunnel_dst', '')
            if dst in node_ips:
                target = node_ips[dst]
                if hostname == target:
                    continue
                # Only create link if at least one end is a core device
                if hostname not in core_set and target not in core_set:
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

    # Ensure all provincial routers connect to at least one core router
    # Find main hub core routers
    hub_nodes = [h for h in core_set if node_categories[h] == 'core-router']
    if hub_nodes:
        hub = hub_nodes[0]  # Primary core router
        for hostname, category in node_categories.items():
            if category == 'provincial-router':
                # Check if this provincial router already has a link to any core
                has_core_link = any(
                    l for l in links
                    if hostname in (l['source'], l['target'])
                    and (l['source'] in core_set or l['target'] in core_set)
                )
                if not has_core_link:
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

    # Core switches connect to core routers
    for hostname, category in node_categories.items():
        if category == 'core-switch':
            has_core_link = any(
                l for l in links
                if hostname in (l['source'], l['target'])
                and any(
                    node_categories.get(l['source']) == 'core-router'
                    or node_categories.get(l['target']) == 'core-router'
                    for _ in [1]
                )
            )
            if not has_core_link and hub_nodes:
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
