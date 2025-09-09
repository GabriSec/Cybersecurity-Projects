import logging
import scapy.all as scapy
import time
from collections import defaultdict
from utils.logger import logger

SCAN_THRESHOLD = 10
recent_connections = defaultdict(set)

TRAFFIC_THRESHOLD = 100
traffic_counter = defaultdict(list)

ALLOWED_PROTOCOLS = {1, 6, 17}  # ICMP=1, TCP=6, UDP=17

def detect_suspicious(pkt):
    detect_port_scan(pkt)
    detect_high_traffic(pkt)
    detect_protocol_anomaly(pkt)

def detect_port_scan(pkt):
    if scapy.TCP in pkt and scapy.IP in pkt:
        src_ip = pkt[scapy.IP].src
        dst_port = pkt[scapy.TCP].dport
        recent_connections[src_ip].add(dst_port)
        if len(recent_connections[src_ip]) > SCAN_THRESHOLD:
            alert = f"Possible port scan from {src_ip}"
            logger.info(alert)
            print(f"[ALERT] {alert}")
            recent_connections[src_ip] = set()

def detect_high_traffic(pkt):
    if scapy.IP not in pkt:
        return
    src_ip = pkt[scapy.IP].src
    now = int(time.time())
    traffic_counter[src_ip].append(now)
    traffic_counter[src_ip] = [t for t in traffic_counter[src_ip] if t >= now - 1]
    if len(traffic_counter[src_ip]) > TRAFFIC_THRESHOLD:
        alert = f"High traffic detected from {src_ip} ({len(traffic_counter[src_ip])} packets/sec)"
        logger.info(alert)
        print(f"[ALERT] {alert}")

def detect_protocol_anomaly(pkt):
    if scapy.IP in pkt and pkt.proto not in ALLOWED_PROTOCOLS:
        alert = f"Unexpected protocol {pkt.proto} from {pkt[scapy.IP].src}"
        logger.info(alert)
        print(f"[ALERT] {alert}")
