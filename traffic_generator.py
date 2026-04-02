from scapy.all import *
import time

IFACE = 'eth0'
TARGET_IP = '172.18.0.3'

# Resolve MAC at startup so Scapy stops broadcasting
TARGET_MAC = getmacbyip(TARGET_IP)
if not TARGET_MAC:
    # Fallback: ARP request to force resolution
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=TARGET_IP), 
                 iface=IFACE, timeout=2, verbose=0)
    TARGET_MAC = ans[0][1].hwsrc if ans else "ff:ff:ff:ff:ff:ff"

print(f"Target MAC resolved: {TARGET_MAC}")

def generate_normal_traffic(target_ip, duration_seconds=60):
    print(f"Generating normal traffic for {duration_seconds}s...")
    start_time = time.time()
    while time.time() - start_time < duration_seconds:
        p = Ether(dst=TARGET_MAC)/IP(dst=target_ip)/TCP(dport=80, flags='S')
        sendp(p, iface=IFACE, verbose=0)
        time.sleep(0.1)

def generate_port_scan(target_ip, port_range=(1, 1024)):
    print(f"Generating port scan attack...")
    for port in range(port_range[0], port_range[1]):
        p = Ether(dst=TARGET_MAC)/IP(src="192.168.1.200", dst=target_ip)/TCP(dport=port, flags='S')
        sendp(p, iface=IFACE, verbose=0)
        time.sleep(0.01)

def generate_ddos_attack(target_ip, duration_seconds=30):
    print(f"Generating DDoS attack for {duration_seconds}s...")
    start_time = time.time()
    while time.time() - start_time < duration_seconds:
        p = Ether(dst=TARGET_MAC)/IP(src="192.168.1.201", dst=target_ip)/TCP(dport=80, flags='S')
        sendp(p, iface=IFACE, verbose=0)

def generate_slow_exfiltration(target_ip, duration_seconds=60):
    print(f"Generating slow exfiltration for {duration_seconds}s...")
    start_time = time.time()
    while time.time() - start_time < duration_seconds:
        p = Ether(dst=TARGET_MAC)/IP(src="192.168.1.202", dst=target_ip)/TCP(dport=443)/Raw(load="X" * 1400)
        sendp(p, iface=IFACE, verbose=0)
        time.sleep(2)

# Run test sequence
generate_normal_traffic(TARGET_IP, duration_seconds=60)
generate_port_scan(TARGET_IP, port_range=(1, 100))
generate_normal_traffic(TARGET_IP, duration_seconds=30)
generate_ddos_attack(TARGET_IP, duration_seconds=30)
generate_slow_exfiltration(TARGET_IP, duration_seconds=60)