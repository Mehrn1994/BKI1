"""Network map routes - Parse core router configs and build topology."""
import os
import re
from flask import Blueprint, jsonify

from app.config import Config

network_map_bp = Blueprint('network_map', __name__)

ROUTER_DIR = os.path.join(Config.BASE_DIR, 'Router')

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
        if ips:
            for ip, mask in ips:
                entry = {'name': iface_name, 'ip': ip, 'mask': mask}
                if desc:
                    entry['description'] = desc.group(1).strip()
                if 'Tunnel' in iface_name:
                    # Get tunnel details
                    src = re.search(r'tunnel source\s+(\S+)', iface_block)
                    dst = re.search(r'tunnel destination\s+(\S+)', iface_block)
                    if src:
                        entry['tunnel_src'] = src.group(1)
                    if dst:
                        entry['tunnel_dst'] = dst.group(1)
                    info['tunnels'].append(entry)
                else:
                    info['interfaces'].append(entry)

    # NAT rules
    for m in re.finditer(r'^ip nat\s+(.+)', content, re.MULTILINE):
        info['nat_rules'].append(m.group(1).strip())

    # OSPF
    for m in re.finditer(r'^router ospf\s+(\d+)\s*\n((?:.*\n)*?)(?=^router\s|^\!)', content, re.MULTILINE):
        networks = re.findall(r'network\s+(\S+)\s+(\S+)\s+area\s+(\S+)', m.group(2))
        info['ospf_processes'].append({
            'process': m.group(1),
            'networks': [{'net': n, 'wildcard': w, 'area': a} for n, w, a in networks]
        })

    # Static routes (first 20)
    routes = re.findall(r'^ip route\s+(.+)', content, re.MULTILINE)
    info['static_routes'] = routes[:20]

    # Crypto maps
    for m in re.finditer(r'^crypto map\s+(\S+)\s+(\d+)', content, re.MULTILINE):
        info['crypto_maps'].append({'name': m.group(1), 'seq': m.group(2)})

    return info


def _abbr_from_hostname(hostname):
    """Extract province abbreviation from hostname."""
    # Format: ModelType-ABBR or ModelType-ABBR-xxx
    parts = hostname.split('-')
    if len(parts) >= 2:
        # Skip model prefix (3825, 3845, ASR1002X, Mo)
        abbr = parts[1]
        if len(parts) >= 3 and abbr in ('M1', 'M2', 'OS', 'Mo'):
            abbr = '-'.join(parts[1:3])
        return abbr
    return hostname


@network_map_bp.route('/api/network-map/topology', methods=['GET'])
def get_topology():
    """Parse all core router configs and return topology data."""
    nodes = []
    links = []

    if not os.path.exists(ROUTER_DIR):
        return jsonify({'nodes': [], 'links': [], 'error': 'Router directory not found'})

    parsed_configs = {}
    for fname in sorted(os.listdir(ROUTER_DIR)):
        fpath = os.path.join(ROUTER_DIR, fname)
        if not os.path.isfile(fpath) or os.path.getsize(fpath) < 100:
            continue

        info = _parse_config(fpath)
        if not info or not info['hostname']:
            continue

        abbr = _abbr_from_hostname(info['hostname'])
        pinfo = PROVINCE_INFO.get(abbr, {})

        node = {
            'id': info['hostname'],
            'abbr': abbr,
            'label': pinfo.get('fa', abbr),
            'x': pinfo.get('x', 50),
            'y': pinfo.get('y', 50),
            'model': info['model'] or fname.split('-')[0],
            'interfaces_count': len(info['interfaces']),
            'tunnels_count': len(info['tunnels']),
            'nat_count': len(info['nat_rules']),
            'ospf_count': len(info['ospf_processes']),
            'static_routes_count': len(info['static_routes']),
            'interfaces': info['interfaces'][:10],
            'tunnels': info['tunnels'][:10],
            'nat_rules': info['nat_rules'][:15],
            'ospf': info['ospf_processes'],
        }
        nodes.append(node)
        parsed_configs[info['hostname']] = info

    # Build links from tunnel destinations
    node_ips = {}
    for node_info in parsed_configs.values():
        for iface in node_info['interfaces']:
            node_ips[iface['ip']] = node_info['hostname']

    seen_links = set()
    for hostname, info in parsed_configs.items():
        for tunnel in info['tunnels']:
            dst = tunnel.get('tunnel_dst', '')
            if dst in node_ips:
                target = node_ips[dst]
                link_key = tuple(sorted([hostname, target]))
                if link_key not in seen_links:
                    seen_links.add(link_key)
                    links.append({
                        'source': hostname,
                        'target': target,
                        'tunnel': tunnel['name'],
                        'src_ip': tunnel.get('tunnel_src', ''),
                        'dst_ip': dst,
                    })

    # Add hub links (all nodes connect to Tehran)
    tehran_nodes = [n['id'] for n in nodes if 'Tehran' in n['id'] or n['abbr'] in ('M1-Tehran', 'M2-Tehran', 'OSTehran')]
    if tehran_nodes:
        hub = tehran_nodes[0]
        for node in nodes:
            if node['id'] != hub and not any(l for l in links if node['id'] in (l['source'], l['target']) and hub in (l['source'], l['target'])):
                link_key = tuple(sorted([node['id'], hub]))
                if link_key not in seen_links:
                    seen_links.add(link_key)
                    links.append({
                        'source': hub,
                        'target': node['id'],
                        'tunnel': 'WAN',
                        'src_ip': '',
                        'dst_ip': '',
                    })

    return jsonify({
        'nodes': nodes,
        'links': links,
        'total_routers': len(nodes),
        'total_links': len(links),
    })
