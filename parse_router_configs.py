"""
Parse all Router config files and extract tunnel information.
Build Excel database with used/free tunnel IPs for VPLS/MPLS.

For each management router, extracts:
- Tunnel name, description, IP address, tunnel source, tunnel destination
- Identifies which 100.100.100.x/31 IPs are used
- Creates per-province sheets in Excel
- Updates vpls_tunnels DB table marking used IPs
"""

import re
import os
import sqlite3
from datetime import datetime
from difflib import SequenceMatcher

ROUTER_DIR = os.path.join(os.path.dirname(__file__), 'Router')
DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'network_ipam.db')
EXCEL_PATH = os.path.join(os.path.dirname(__file__), 'data', 'VPLS_MPLS_Tunnel_IPs.xlsx')

# Province abbreviation mapping from filenames
# Names MUST match the province names used in generate_vpls_tunnels.py
PROVINCE_MAP = {
    'ALZ': 'Alborz', 'ARD': 'Ardabil', 'AZGH': 'West Azerbaijan',
    'AZSH': 'East Azerbaijan', 'BSH': 'Bushehr',
    'CHB': 'Chaharmahal and Bakhtiari',
    'ESF': 'Isfahan', 'FRS': 'Fars', 'GIL': 'Gilan', 'GLS': 'Golestan',
    'HMD': 'Hamadan', 'HMZ': 'Hormozgan', 'ILM': 'Ilam',
    'KHR': 'Razavi Khorasan', 'KHRJ': 'South Khorasan',
    'KHZ': 'Khuzestan', 'KNB': 'Kohgiluyeh and Boyer-Ahmad',
    'KRD': 'Kurdistan',
    'KRM': 'Kerman', 'KRMJ': 'Kermanshah', 'KRSH': 'Kermanshah',
    'LOR': 'Lorestan', 'MAZ': 'Mazandaran', 'MRZ': 'Markazi',
    'QOM': 'Qom', 'QZV': 'Qazvin', 'SMN': 'Semnan',
    'SNB': 'Sistan and Baluchestan', 'YZD': 'Yazd', 'ZNJ': 'Zanjan',
    'M1': 'Tehran', 'M2': 'Tehran', 'OSTehran': 'Tehran',
    'Tehran': 'Tehran', 'KhShomali': 'North Khorasan',
}

# Province abbreviation → Persian name (matching lan_ips.province)
PROVINCE_PERSIAN_MAP = {
    'ALZ': 'البرز', 'ARD': 'اردبیل', 'AZGH': 'آذربایجان غربی',
    'AZSH': 'آذربایجان شرقی', 'BSH': 'بوشهر',
    'CHB': 'چهارمحال و بختیاری',
    'ESF': 'اصفهان', 'FRS': 'فارس', 'GIL': 'گیلان', 'GLS': 'گلستان',
    'HMD': 'همدان', 'HMZ': 'هرمزگان', 'ILM': 'ایلام',
    'KHR': 'خراسان رضوی', 'KHRJ': 'خراسان جنوبی',
    'KHZ': 'خوزستان', 'KNB': 'کهگیلویه و بویراحمد',
    'KRD': 'کردستان',
    'KRM': 'کرمان', 'KRMJ': 'کرمانشاه', 'KRSH': 'کرمانشاه',
    'LOR': 'لرستان', 'MAZ': 'مازندران', 'MRZ': 'مرکزی',
    'QOM': 'قم', 'QZV': 'قزوین', 'SMN': 'سمنان',
    'SNB': 'سیستان و بلوچستان', 'YZD': 'یزد', 'ZNJ': 'زنجان',
    'M1': 'تهران', 'M2': 'تهران', 'OSTehran': 'تهران',
    'Tehran': 'تهران', 'KhShomali': 'خراسان شمالی',
}

# ==================== PERSIAN ↔ ENGLISH TRANSLITERATION ====================
PERSIAN_TO_LATIN = {
    'ا': 'a', 'آ': 'a', 'ب': 'b', 'پ': 'p', 'ت': 't', 'ث': 's',
    'ج': 'j', 'چ': 'ch', 'ح': 'h', 'خ': 'kh', 'د': 'd', 'ذ': 'z',
    'ر': 'r', 'ز': 'z', 'ژ': 'zh', 'س': 's', 'ش': 'sh', 'ص': 's',
    'ض': 'z', 'ط': 't', 'ظ': 'z', 'ع': 'a', 'غ': 'gh', 'ف': 'f',
    'ق': 'gh', 'ک': 'k', 'گ': 'g', 'ل': 'l', 'م': 'm', 'ن': 'n',
    'و': 'v', 'ه': 'h', 'ی': 'i', 'ي': 'i', 'ئ': '', 'ء': '',
    'ة': 'h', 'إ': 'e', 'أ': 'a',
}

# Infra keywords - Serial interfaces with these descriptions are NOT branch PTMP
INFRA_KEYWORDS = [
    'E1', 'ZirSakht', 'ZIRSAKHT', 'zirsakht', 'TDM', 'MPLS',
    'HQ', 'Mo-', 'PTMP TEH', 'PTMP-TEH', 'PtmpTEH', 'Markazi',
    'UpLink', 'uplink', 'UP-LINK', 'up link', 'Trunk',
]

# Prefixes to strip from English names before matching
EN_PREFIXES_TO_STRIP = ['Bj-', 'Baj-', 'Kh-', 'ATM-', 'Bje-']

# Prefixes to strip from Persian names before matching
FA_PREFIXES_TO_STRIP = ['باجه ', 'شعبه ', 'نقطه ', 'خودپرداز ']


def transliterate_persian(text):
    """Convert Persian text to approximate Latin transliteration for matching."""
    if not text:
        return ''
    result = []
    for ch in text:
        if ch in PERSIAN_TO_LATIN:
            result.append(PERSIAN_TO_LATIN[ch])
        elif ch == ' ' or ch == '\u200c':  # space or half-space
            continue  # remove spaces for matching
        elif ch.isascii():
            result.append(ch.lower())
        # Skip unknown characters (diacritics, etc.)
    return ''.join(result)


def consonant_skeleton(text):
    """Extract consonant skeleton for phonetic matching.
    Removes vowels and normalizes similar sounds to improve matching.
    'Ardestan' → 'rdstm', 'اردستان' → 'rdstan' → 'rdstn'
    """
    if not text:
        return ''
    t = text.lower()
    # Normalize common phonetic equivalents
    t = t.replace('gh', 'g').replace('kh', 'k').replace('sh', 's')
    t = t.replace('ch', 'c').replace('zh', 'z').replace('ph', 'f')
    t = t.replace('ou', 'u').replace('oo', 'u').replace('ee', 'i')
    # Remove vowels
    t = re.sub(r'[aeiou]', '', t)
    return t


def normalize_en_name(name):
    """Normalize an English branch name for matching."""
    if not name:
        return ''
    # Strip known prefixes
    for prefix in EN_PREFIXES_TO_STRIP:
        if name.startswith(prefix):
            name = name[len(prefix):]
    # Strip trailing bandwidth suffixes: -512, -448K, -512K, -256, -64, -384K, -1M, -2M etc.
    name = re.sub(r'[-\s]+\d+[kKmM]?\s*$', '', name)
    # Also strip standalone numbers at end after space/hyphen (like "Bahar 512")
    name = re.sub(r'[-\s]+\d{2,4}$', '', name)
    # Remove spaces, hyphens, underscores; lowercase
    return re.sub(r'[\s\-_]', '', name).lower()


def normalize_fa_name(name):
    """Normalize a Persian branch name for matching."""
    if not name:
        return ''
    # Strip parenthetical notes: "ایمانشهر (اشترجان قدیم)" → "ایمانشهر"
    name = re.sub(r'\s*\([^)]*\)', '', name).strip()
    # Strip known Persian prefixes
    for prefix in FA_PREFIXES_TO_STRIP:
        if name.startswith(prefix):
            name = name[len(prefix):]
    # Remove province name suffix (e.g., "اردستان اصفهان" → "اردستان")
    # This is handled per-province during matching
    return name.strip()


def match_branch_names(en_names, persian_branches, province_name=''):
    """
    Match English branch names to Persian branch names using transliteration.

    Args:
        en_names: list of English names from router config
        persian_branches: list of dicts with 'branch_name', 'octet2', 'octet3' from lan_ips

    Returns:
        dict: {en_name: {'persian': str, 'lan_ip': str, 'confidence': float}} or None
    """
    matches = {}

    # Pre-process Persian names: normalize + transliterate
    fa_candidates = []
    for pb in persian_branches:
        raw_name = pb['branch_name']
        if not raw_name:
            continue

        # Normalize Persian name
        cleaned = normalize_fa_name(raw_name)

        # Also try without province suffix
        if province_name:
            cleaned_no_prov = cleaned.replace(province_name, '').strip()
            if cleaned_no_prov:
                cleaned = cleaned_no_prov

        # Transliterate to Latin
        latin = transliterate_persian(cleaned)

        # Generate vowel variants (و can be u/o/v in English)
        latin_u = latin.replace('v', 'u')
        latin_o = latin.replace('v', 'o')

        # Consonant skeleton for phonetic matching
        cons = consonant_skeleton(latin)

        # Also try just the first word (for compound names like "چرمهین لنجان")
        first_word = raw_name.split()[0] if ' ' in raw_name else ''
        first_word_latin = transliterate_persian(first_word) if first_word else ''

        fa_candidates.append({
            'original': raw_name,
            'cleaned': cleaned,
            'latin': latin,
            'latin_u': latin_u,
            'latin_o': latin_o,
            'consonants': cons,
            'first_word_latin': first_word_latin,
            'octet2': pb['octet2'],
            'octet3': pb['octet3'],
        })

    for en_name in en_names:
        en_norm = normalize_en_name(en_name)
        if not en_norm:
            continue

        en_cons = consonant_skeleton(en_norm)

        best_match = None
        best_score = 0.0

        for fc in fa_candidates:
            fa_latin = fc['latin']
            if not fa_latin:
                continue

            # Method 1: SequenceMatcher on base transliteration
            score = SequenceMatcher(None, en_norm, fa_latin).ratio()

            # Method 2: Try vowel variants (و → u/o)
            score_u = SequenceMatcher(None, en_norm, fc['latin_u']).ratio()
            score_o = SequenceMatcher(None, en_norm, fc['latin_o']).ratio()
            score = max(score, score_u, score_o)

            # Method 3: Consonant skeleton match (handles vowel differences)
            if fc['consonants'] and en_cons:
                cons_score = SequenceMatcher(None, en_cons, fc['consonants']).ratio()
                if cons_score >= 0.80:
                    score = max(score, cons_score * 0.95)  # slightly below direct match

            # Method 4: Containment check (one contains the other)
            if en_norm in fa_latin or fa_latin in en_norm:
                score = max(score, 0.85)
            if fc['latin_u'] and (en_norm in fc['latin_u'] or fc['latin_u'] in en_norm):
                score = max(score, 0.85)

            # Method 5: First word match (for compound Persian names)
            if fc['first_word_latin'] and len(fc['first_word_latin']) >= 4:
                fw_score = SequenceMatcher(None, en_norm, fc['first_word_latin']).ratio()
                fw_score_u = SequenceMatcher(None, en_norm, fc['first_word_latin'].replace('v', 'u')).ratio()
                fw_best = max(fw_score, fw_score_u)
                if fw_best >= 0.80:
                    score = max(score, fw_best * 0.92)

            # Method 6: Starting substring match (first N chars)
            min_len = min(len(en_norm), len(fa_latin))
            if min_len >= 4:
                prefix_match = 0
                for i in range(min_len):
                    if en_norm[i] == fa_latin[i]:
                        prefix_match += 1
                    else:
                        break
                if prefix_match >= 4:
                    prefix_score = prefix_match / max(len(en_norm), len(fa_latin))
                    score = max(score, prefix_score + 0.2)

            if score > best_score:
                best_score = score
                best_match = fc

        # Threshold: 0.68 to catch more borderline matches
        if best_match and best_score >= 0.68:
            lan_ip = f"10.{best_match['octet2']}.{best_match['octet3']}.0"
            matches[en_name] = {
                'persian': best_match['original'],
                'lan_ip': lan_ip,
                'confidence': round(best_score, 3),
            }

    return matches


def extract_province(filename):
    """Extract province abbreviation from filename."""
    # e.g. '3825-ALZ-7' -> 'ALZ', 'ASR1002X-ESF-Feb-15...' -> 'ESF'
    parts = filename.replace('.', '-').split('-')
    for p in parts:
        if p in PROVINCE_MAP:
            return p, PROVINCE_MAP[p]
    # Try multi-part like 'OSTehran', 'KhShomali'
    for key in PROVINCE_MAP:
        if key in filename:
            return key, PROVINCE_MAP[key]
    return filename, filename


def parse_serial_interfaces(filepath):
    """Parse a single router config file and extract Serial sub-interfaces (PTMP)."""
    serials = []
    with open(filepath, 'r', errors='ignore') as f:
        lines = f.readlines()

    # Extract hostname from config
    hostname = None
    for line in lines:
        if line.startswith('hostname '):
            hostname = line.strip().replace('hostname ', '').strip()
            break

    current = None

    for line in lines:
        line = line.rstrip()

        if line.startswith('interface Serial'):
            # Save previous interface
            if current is not None:
                serials.append(current)

            intf_name = line.replace('interface ', '').strip()
            current = {
                'interface_name': intf_name,
                'description': '',
                'branch_name_en': None,
                'bandwidth': None,
                'ip_type': None,
                'ip_address': None,
                'ip_mask': None,
                'encapsulation': None,
            }

        elif current is not None:
            stripped = line.strip()

            if stripped.startswith('description '):
                desc_raw = stripped.replace('description ', '').strip()
                current['description'] = desc_raw

                # Parse branch name from ** BranchName - Bandwidth ** format
                match = re.match(r'\*\*\s*(.+?)\s*\*\*', desc_raw)
                if match:
                    inner = match.group(1).strip()
                    if ' - ' in inner:
                        parts = inner.rsplit(' - ', 1)
                        current['branch_name_en'] = parts[0].strip()
                        current['bandwidth'] = parts[1].strip()
                    else:
                        # Check if it's an infrastructure interface
                        is_infra = any(kw.lower() in inner.lower() for kw in INFRA_KEYWORDS)
                        if not is_infra:
                            current['branch_name_en'] = inner
                else:
                    # No ** pattern - try simple description
                    desc_clean = desc_raw.strip('"').strip()
                    if desc_clean and not any(kw.lower() in desc_clean.lower() for kw in INFRA_KEYWORDS):
                        if ' - ' in desc_clean:
                            parts = desc_clean.rsplit(' - ', 1)
                            name_part = parts[0].strip()
                            bw_part = parts[1].strip()
                            # Check if the second part looks like bandwidth
                            if re.match(r'^\d+[kKmM]?$', bw_part):
                                current['branch_name_en'] = name_part
                                current['bandwidth'] = bw_part

            elif stripped.startswith('bandwidth '):
                bw = stripped.replace('bandwidth ', '').strip()
                if current['bandwidth'] is None:
                    current['bandwidth'] = bw

            elif stripped.startswith('ip unnumbered'):
                current['ip_type'] = 'unnumbered'

            elif stripped.startswith('ip address '):
                parts = stripped.split()
                if len(parts) >= 3:
                    current['ip_type'] = 'addressed'
                    current['ip_address'] = parts[2]
                    current['ip_mask'] = parts[3] if len(parts) > 3 else ''

            elif stripped.startswith('no ip address'):
                current['ip_type'] = 'no_ip'

            elif stripped.startswith('encapsulation '):
                current['encapsulation'] = stripped.replace('encapsulation ', '').strip()

            elif line.startswith('interface ') or line.startswith('!'):
                # End of current interface block
                serials.append(current)
                current = None

    # Last interface
    if current is not None:
        serials.append(current)

    return serials, hostname


def import_serial_to_db():
    """Parse all router configs and import Serial interfaces to ptmp_connections table.

    Returns the total number of imported records.
    """
    print("=" * 60)
    print("IMPORTING SERIAL INTERFACES (PTMP)")
    print("=" * 60)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Create table if needed
    cursor.execute("""CREATE TABLE IF NOT EXISTS ptmp_connections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        interface_name TEXT NOT NULL,
        description TEXT,
        branch_name TEXT,
        branch_name_en TEXT,
        bandwidth TEXT,
        ip_type TEXT,
        ip_address TEXT,
        ip_mask TEXT,
        encapsulation TEXT,
        province TEXT,
        province_abbr TEXT,
        router_hostname TEXT,
        router_file TEXT,
        status TEXT DEFAULT 'Used',
        username TEXT,
        reservation_date TEXT,
        lan_ip TEXT)""")

    # Clear only auto-imported data (preserve manual entries)
    cursor.execute("DELETE FROM ptmp_connections WHERE status = 'Used'")
    print(f"  Cleared previous imported PTMP data")

    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    config_files = sorted(os.listdir(ROUTER_DIR))
    total = 0
    total_matched = 0
    total_branches = 0

    for filename in config_files:
        filepath = os.path.join(ROUTER_DIR, filename)
        if os.path.isdir(filepath):
            continue
        if os.path.getsize(filepath) < 100:
            continue

        prov_abbr, prov_english = extract_province(filename)
        prov_persian = PROVINCE_PERSIAN_MAP.get(prov_abbr, '')

        serials, hostname = parse_serial_interfaces(filepath)
        if not serials:
            continue

        # Get branch names that have actual branch_name_en (not infra)
        branch_en_names = [s['branch_name_en'] for s in serials if s['branch_name_en']]

        # Load Persian branch names from lan_ips for this province
        persian_branches = []
        if prov_persian:
            cursor.execute("""
                SELECT DISTINCT branch_name, octet2, octet3
                FROM lan_ips
                WHERE province = ? AND branch_name IS NOT NULL AND branch_name != ''
            """, (prov_persian,))
            persian_branches = [dict(r) for r in cursor.fetchall()]

        # Run transliteration matching
        name_matches = {}
        if branch_en_names and persian_branches:
            name_matches = match_branch_names(branch_en_names, persian_branches, prov_persian)

        matched_count = len(name_matches)
        branch_count = len(branch_en_names)
        total_matched += matched_count
        total_branches += branch_count

        # Insert all serial interfaces
        for s in serials:
            en_name = s['branch_name_en']
            persian_name = None
            lan_ip = None

            if en_name and en_name in name_matches:
                m = name_matches[en_name]
                persian_name = m['persian']
                lan_ip = m['lan_ip']

            cursor.execute("""
                INSERT INTO ptmp_connections
                (interface_name, description, branch_name, branch_name_en,
                 bandwidth, ip_type, ip_address, ip_mask, encapsulation,
                 province, province_abbr, router_hostname, router_file,
                 status, username, reservation_date, lan_ip)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Used', 'imported', ?, ?)
            """, (
                s['interface_name'], s['description'],
                persian_name, en_name,
                s['bandwidth'], s['ip_type'], s['ip_address'], s['ip_mask'],
                s['encapsulation'],
                prov_persian, prov_abbr,
                hostname or filename, filename,
                now, lan_ip
            ))
            total += 1

        match_pct = (matched_count / branch_count * 100) if branch_count > 0 else 0
        print(f"  {filename} ({prov_persian or prov_english}): "
              f"{len(serials)} serial, {branch_count} branches, "
              f"{matched_count} matched ({match_pct:.0f}%)")

    conn.commit()

    # Create indexes
    try:
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ptmp_branch ON ptmp_connections(branch_name)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ptmp_branch_en ON ptmp_connections(branch_name_en)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ptmp_province ON ptmp_connections(province)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ptmp_status ON ptmp_connections(status)")
    except Exception:
        pass

    conn.close()

    total_pct = (total_matched / total_branches * 100) if total_branches > 0 else 0
    print(f"\n  TOTAL: {total} serial interfaces imported")
    print(f"  MATCHED: {total_matched}/{total_branches} branch names ({total_pct:.0f}%)")
    return total


def parse_router_config(filepath):
    """Parse a single router config file and extract tunnel interfaces."""
    tunnels = []
    with open(filepath, 'r', errors='ignore') as f:
        lines = f.readlines()

    current_tunnel = None

    for line in lines:
        line = line.rstrip()

        if line.startswith('interface Tunnel'):
            # Save previous tunnel
            if current_tunnel and current_tunnel.get('ip_address'):
                tunnels.append(current_tunnel)

            tunnel_name = line.replace('interface ', '').strip()
            current_tunnel = {
                'tunnel_name': tunnel_name,
                'description': '',
                'ip_address': '',
                'ip_mask': '',
                'tunnel_source': '',
                'tunnel_destination': '',
            }

        elif current_tunnel is not None:
            stripped = line.strip()

            if stripped.startswith('description '):
                current_tunnel['description'] = stripped.replace('description ', '').strip().strip('"')

            elif stripped.startswith('ip address '):
                parts = stripped.split()
                if len(parts) >= 3:
                    current_tunnel['ip_address'] = parts[2]
                    current_tunnel['ip_mask'] = parts[3] if len(parts) > 3 else ''

            elif stripped.startswith('tunnel source '):
                current_tunnel['tunnel_source'] = stripped.replace('tunnel source ', '').strip()

            elif stripped.startswith('tunnel destination '):
                current_tunnel['tunnel_destination'] = stripped.replace('tunnel destination ', '').strip()

            elif line.startswith('interface ') or line.startswith('!'):
                if current_tunnel.get('ip_address'):
                    tunnels.append(current_tunnel)
                if line.startswith('interface ') and not line.startswith('interface Tunnel'):
                    current_tunnel = None
                elif line.startswith('!'):
                    current_tunnel = None

    # Don't forget the last tunnel
    if current_tunnel and current_tunnel.get('ip_address'):
        tunnels.append(current_tunnel)

    return tunnels


def main():
    print("=" * 80)
    print("PARSING ROUTER CONFIGS - EXTRACTING TUNNEL IPs")
    print("=" * 80)

    all_tunnels = []  # (province_abbr, province_name, router_file, tunnel_data)
    vpls_used_ips = {}  # (province, pair_ip) -> tunnel_info (only 100.100.100.x range)

    config_files = sorted(os.listdir(ROUTER_DIR))
    print(f"\nFound {len(config_files)} router config files")

    for filename in config_files:
        filepath = os.path.join(ROUTER_DIR, filename)
        if os.path.isdir(filepath):
            # Check for files inside directories
            for sub in os.listdir(filepath):
                subpath = os.path.join(filepath, sub)
                if os.path.isfile(subpath):
                    filepath = subpath
                    break
            else:
                continue

        prov_abbr, prov_name = extract_province(filename)
        tunnels = parse_router_config(filepath)

        print(f"\n  {filename} ({prov_name}): {len(tunnels)} tunnels")

        for t in tunnels:
            all_tunnels.append({
                'province_abbr': prov_abbr,
                'province_name': prov_name,
                'router_file': filename,
                **t
            })

            # Track 100.100.100.x IPs (VPLS/MPLS range) - per province
            ip = t['ip_address']
            if ip.startswith('100.100.10'):
                # Find the /31 pair base (even IP)
                parts = ip.split('.')
                last = int(parts[3])
                base = last - (last % 2)
                pair_base = f"{parts[0]}.{parts[1]}.{parts[2]}.{base}"
                pair_ip = f"{pair_base}/31"

                key = (prov_name, pair_ip)
                vpls_used_ips[key] = {
                    'tunnel_name': t['tunnel_name'],
                    'description': t['description'],
                    'ip_address': ip,
                    'tunnel_source': t['tunnel_source'],
                    'tunnel_destination': t['tunnel_destination'],
                    'province': prov_name,
                    'province_abbr': prov_abbr,
                    'router': filename,
                }
                print(f"    VPLS/MPLS: {t['tunnel_name']} -> {ip} ({t['description']})")

    print(f"\n{'=' * 60}")
    print(f"SUMMARY")
    print(f"{'=' * 60}")
    print(f"Total tunnels found: {len(all_tunnels)}")
    print(f"VPLS/MPLS (100.100.x.x) used IP pairs (per-province): {len(vpls_used_ips)}")

    # ==================== UPDATE DATABASE ====================
    print(f"\n{'=' * 60}")
    print("UPDATING DATABASE")
    print(f"{'=' * 60}")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Ensure table exists
    cursor.execute("""CREATE TABLE IF NOT EXISTS vpls_tunnels (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT,
        hub_ip TEXT,
        branch_ip TEXT,
        tunnel_name TEXT,
        description TEXT,
        province TEXT,
        branch_name TEXT,
        wan_ip TEXT,
        tunnel_dest TEXT,
        status TEXT DEFAULT 'Free',
        username TEXT,
        reservation_date TEXT)""")

    # Mark used IPs in the database (per-province matching)
    updated = 0
    for (province, pair_ip), info in vpls_used_ips.items():
        cursor.execute("""
            UPDATE vpls_tunnels
            SET status = 'Used',
                tunnel_name = ?,
                description = ?,
                wan_ip = ?,
                tunnel_dest = ?,
                username = 'imported',
                reservation_date = ?
            WHERE ip_address = ? AND province = ? AND LOWER(status) = 'free'
        """, (
            info['tunnel_name'],
            info['description'],
            info['tunnel_source'],
            info['tunnel_destination'],
            datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            pair_ip,
            province
        ))
        if cursor.rowcount > 0:
            updated += 1

    conn.commit()

    # Show stats
    cursor.execute("SELECT status, COUNT(*) FROM vpls_tunnels GROUP BY status")
    print(f"\nDatabase status after import:")
    for row in cursor.fetchall():
        print(f"  {row[0]}: {row[1]}")

    conn.close()
    print(f"Updated {updated} tunnel IP pairs to 'Used'")

    # ==================== GENERATE EXCEL ====================
    print(f"\n{'=' * 60}")
    print("GENERATING EXCEL FILE")
    print(f"{'=' * 60}")

    try:
        import pandas as pd

        # Sheet 1: All tunnels summary
        df_all = pd.DataFrame(all_tunnels)
        df_all = df_all[['province_abbr', 'province_name', 'router_file',
                         'tunnel_name', 'description', 'ip_address', 'ip_mask',
                         'tunnel_source', 'tunnel_destination']]

        # Sheet 2: VPLS/MPLS used IPs
        vpls_rows = []
        for (prov, pair_ip), info in sorted(vpls_used_ips.items()):
            vpls_rows.append({
                'IP Pair (/31)': pair_ip,
                'Tunnel Name': info['tunnel_name'],
                'Description': info['description'],
                'Tunnel IP': info['ip_address'],
                'Tunnel Source': info['tunnel_source'],
                'Tunnel Destination': info['tunnel_destination'],
                'Province': info['province'],
                'Province Code': info['province_abbr'],
                'Router': info['router'],
                'Status': 'Used',
                'User': 'imported',
                'Date': datetime.now().strftime('%Y-%m-%d')
            })
        df_vpls_used = pd.DataFrame(vpls_rows)

        # Sheet 3: Free VPLS IPs
        conn2 = sqlite3.connect(DB_PATH)
        df_free = pd.read_sql_query(
            "SELECT ip_address, hub_ip, branch_ip, status FROM vpls_tunnels WHERE LOWER(status) = 'free' ORDER BY id",
            conn2
        )
        conn2.close()

        # Per-province sheets
        province_data = {}
        for t in all_tunnels:
            prov = t['province_abbr']
            if prov not in province_data:
                province_data[prov] = []
            province_data[prov].append(t)

        with pd.ExcelWriter(EXCEL_PATH, engine='openpyxl') as writer:
            df_all.to_excel(writer, sheet_name='All_Tunnels', index=False)
            if len(vpls_rows) > 0:
                df_vpls_used.to_excel(writer, sheet_name='VPLS_Used', index=False)
            df_free.to_excel(writer, sheet_name='VPLS_Free', index=False)

            # Per-province sheets
            for prov_abbr in sorted(province_data.keys()):
                sheet_name = prov_abbr[:31]  # Excel sheet name max 31 chars
                df_prov = pd.DataFrame(province_data[prov_abbr])
                df_prov.to_excel(writer, sheet_name=sheet_name, index=False)

        print(f"Excel file generated: {EXCEL_PATH}")
        print(f"  Sheets: All_Tunnels, VPLS_Used, VPLS_Free + {len(province_data)} province sheets")

    except Exception as e:
        print(f"Excel generation error: {e}")
        import traceback
        traceback.print_exc()

    # ==================== IMPORT SERIAL INTERFACES (PTMP) ====================
    import_serial_to_db()

    print(f"\n{'=' * 80}")
    print("DONE!")
    print(f"{'=' * 80}")


if __name__ == '__main__':
    main()
