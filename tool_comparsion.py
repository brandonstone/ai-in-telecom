import re
from datetime import datetime
from collections import defaultdict

# ── Suricata Parser ──────────────────────────────────────────────────────────

def parse_suricata_log(log_file):
    """
    Parse Suricata fast.log into structured alert records.
    """
    alerts = []
    pattern = re.compile(
        r'(?P<timestamp>\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)\s+'
        r'\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+'
        r'(?P<msg>.+?)\s+\[\*\*\]\s+'
        r'.*?\{(?P<proto>\w+)\}\s+'
        r'(?P<src_ip>[\d.]+):(?P<src_port>\d+)\s+->\s+'
        r'(?P<dst_ip>[\d.]+):(?P<dst_port>\d+)'
    )

    with open(log_file) as f:
        for line in f:
            m = pattern.search(line)
            if not m:
                continue

            src_ip  = m.group('src_ip')
            msg     = m.group('msg').strip()
            sid     = int(m.group('sid'))

            # Classify attack type by source IP and rule
            if src_ip == '192.168.1.200':
                attack_type = 'Port Scan'
            elif src_ip == '192.168.1.201':
                if 'DDoS' in msg:
                    attack_type = 'DDoS'
                else:
                    attack_type = 'DDoS'       # still DDoS traffic even if scan rule fires
            elif src_ip == '192.168.1.202':
                attack_type = 'Slow Exfiltration'
            else:
                attack_type = 'Normal Traffic'

            alerts.append({
                'timestamp': datetime.strptime(m.group('timestamp'), '%m/%d/%Y-%H:%M:%S.%f'),
                'sid':        sid,
                'msg':        msg,
                'proto':      m.group('proto'),
                'src_ip':     src_ip,
                'src_port':   int(m.group('src_port')),
                'dst_ip':     m.group('dst_ip'),
                'dst_port':   int(m.group('dst_port')),
                'attack_type': attack_type,
                'system':     'Suricata'
            })

    return alerts


# ── Zeek Parser ──────────────────────────────────────────────────────────────

def parse_zeek_log(log_file):
    """
    Parse Zeek notice.log into structured alert records.
    Skips header lines starting with #.
    """
    alerts = []
    fields = []

    with open(log_file) as f:
        for line in f:
            line = line.strip()
            if line.startswith('#fields'):
                fields = line.split('\t')[1:]
                continue
            if line.startswith('#'):
                continue
            if not fields:
                continue

            parts = line.split('\t')
            row   = dict(zip(fields, parts))

            src_ip = row.get('src', '-')
            dst_port = int(row.get('p', 0)) if row.get('p', '-') != '-' else 0

            # Classify by source IP
            if src_ip == '192.168.1.200':
                attack_type = 'Port Scan'
            elif src_ip == '192.168.1.201':
                attack_type = 'DDoS'
            elif src_ip == '192.168.1.202':
                attack_type = 'Slow Exfiltration'
            else:
                attack_type = 'Normal Traffic'

            # Extract packet count and duration from msg
            pkt_match = re.search(r'(\d+) pkts in ([\d.]+) sec', row.get('msg', ''))
            pkt_count = int(pkt_match.group(1))  if pkt_match else None
            duration  = float(pkt_match.group(2)) if pkt_match else None

            alerts.append({
                'timestamp':   float(row.get('ts', 0)),
                'uid':         row.get('uid', ''),
                'src_ip':      src_ip,
                'dst_ip':      row.get('dst', '-'),
                'dst_port':    dst_port,
                'note':        row.get('note', ''),
                'msg':         row.get('msg', ''),
                'pkt_count':   pkt_count,
                'duration':    duration,
                'attack_type': attack_type,
                'system':      'Zeek'
            })

    return alerts


# ── Comparison Analysis ───────────────────────────────────────────────────────

def analyze_results(suricata_alerts, zeek_alerts):
    """
    Build comparison summary across attack types.
    """
    attack_types = ['Port Scan', 'DDoS', 'Slow Exfiltration', 'Normal Traffic']

    # Count alerts per system per attack type
    sur_counts  = defaultdict(int)
    zeek_counts = defaultdict(int)

    for a in suricata_alerts:
        sur_counts[a['attack_type']] += 1
    for a in zeek_alerts:
        zeek_counts[a['attack_type']] += 1

    # Detection latency — first alert timestamp per attack type
    sur_first  = {}
    zeek_first = {}

    for a in sorted(suricata_alerts, key=lambda x: x['timestamp']):
        if a['attack_type'] not in sur_first:
            sur_first[a['attack_type']] = a['timestamp']

    for a in sorted(zeek_alerts, key=lambda x: x['timestamp']):
        if a['attack_type'] not in zeek_first:
            zeek_first[a['attack_type']] = a['timestamp']

    # Print summary table
    print("=" * 72)
    print(f"{'DETECTION RESULTS COMPARISON':^72}")
    print("=" * 72)
    print(f"{'Attack Type':<22} {'Suricata Alerts':>16} {'Zeek Alerts':>14} {'Winner':>12}")
    print("-" * 72)

    for at in attack_types:
        s = sur_counts.get(at, 0)
        z = zeek_counts.get(at, 0)

        if at == 'Normal Traffic':
            # Lower is better for false positives
            winner = 'Suricata (fewer FP)' if s < z else 'Zeek (fewer FP)' if z < s else 'Tie'
        elif at == 'Slow Exfiltration':
            winner = 'Zeek (correct class)' if z > 0 else 'Neither'
        else:
            winner = 'Tie' if s > 0 and z > 0 else 'Suricata' if s > 0 else 'Zeek'

        print(f"{at:<22} {s:>16} {z:>14} {winner:>12}")

    print("=" * 72)

    # Detection latency comparison
    print(f"\n{'DETECTION LATENCY (first alert per attack type)':^72}")
    print("-" * 72)
    print(f"{'Attack Type':<22} {'Suricata':>24} {'Zeek':>24}")
    print("-" * 72)
    for at in attack_types[:3]:
        s_time = sur_first.get(at, 'Not detected')
        z_time = zeek_first.get(at, 'Not detected')
        s_str  = s_time.strftime('%H:%M:%S.%f')[:12] if isinstance(s_time, datetime) else s_time
        z_str  = str(z_time)[:12] if not isinstance(z_time, str) else z_time
        print(f"{at:<22} {s_str:>24} {z_str:>24}")

    print("=" * 72)

    # Misclassification note
    slow_sur = [a for a in suricata_alerts if a['attack_type'] == 'Slow Exfiltration']
    if slow_sur:
        msgs = set(a['msg'] for a in slow_sur)
        print(f"\nNOTE: Suricata fired {len(slow_sur)} alerts on slow exfiltration")
        print(f"      but classified as: {msgs}")
        print(f"      (no exfiltration signature exists — wrong classification)")

    return {
        'suricata_counts': dict(sur_counts),
        'zeek_counts':     dict(zeek_counts),
        'suricata_first':  sur_first,
        'zeek_first':      zeek_first
    }


# ── Run ───────────────────────────────────────────────────────────────────────

suricata_alerts = parse_suricata_log('logs/suricata/fast.log')
zeek_alerts     = parse_zeek_log('logs/zeek/notice.log')

print(f"Suricata total alerts : {len(suricata_alerts)}")
print(f"Zeek total alerts     : {len(zeek_alerts)}\n")

results = analyze_results(suricata_alerts, zeek_alerts)