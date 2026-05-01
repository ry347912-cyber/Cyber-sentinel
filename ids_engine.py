"""
NetGuard IDS Engine
Packet capture with Scapy + ML-based anomaly detection
Requires: sudo / root privileges for raw packet capture
"""

import time
import threading
from datetime import datetime
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS
from ml_model import MLModel


class IDSEngine:
    def __init__(self, db):
        self.db = db
        self.ml_model = MLModel()

        # Config (changeable via API)
        self.ml_enabled = True
        self.deep_inspect = False
        self.auto_block = True
        self.threshold = 500  # packets/sec to trigger alert

        # State
        self.capturing = False
        self.total_packets = 0
        self.total_attacks = 0
        self.blocked_count = 0
        self.blocked_ips = set()
        self.start_time = time.time()

        # Traffic tracking (per IP, rolling 1s window)
        self.ip_packet_count = defaultdict(int)
        self.ip_port_set = defaultdict(set)
        self.traffic_history = deque(maxlen=60)
        self._lock = threading.Lock()

        # Reset counters every second
        t = threading.Thread(target=self._counter_reset_loop, daemon=True)
        t.start()

    # ── Public Methods ─────────────────────────────────

    def start_capture(self, interface=None):
        """Start sniffing packets. Run as root/sudo."""
        self.capturing = True
        print(f"[IDS] Starting packet capture on {interface or 'all interfaces'}...")
        try:
            sniff(
                iface=interface,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: not self.capturing,
            )
        except Exception as e:
            print(f"[IDS] Capture error: {e}")
        self.capturing = False

    def stop_capture(self):
        self.capturing = False

    def block_ip(self, ip: str):
        self.blocked_ips.add(ip)
        self.blocked_count += 1
        print(f"[IDS] Blocked IP: {ip}")

    def get_uptime(self) -> str:
        secs = int(time.time() - self.start_time)
        h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
        return f"{h}h {m}m {s}s"

    def get_traffic_history(self):
        with self._lock:
            return list(self.traffic_history)

    # ── Packet Processing ──────────────────────────────

    def _process_packet(self, pkt):
        if not pkt.haslayer(IP):
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        # Skip blocked IPs
        if src_ip in self.blocked_ips:
            return

        self.total_packets += 1

        with self._lock:
            self.ip_packet_count[src_ip] += 1

        # Extract features
        features = self._extract_features(pkt, src_ip)

        # Rule-based detection first (fast)
        alert = self._rule_based_detect(pkt, src_ip, dst_ip, features)

        # ML detection if enabled and no rule matched
        if not alert and self.ml_enabled:
            alert = self._ml_detect(features, src_ip, dst_ip, pkt)

        if alert:
            self.total_attacks += 1
            self.db.save_alert(alert)
            if self.auto_block and alert["severity"] in ("CRITICAL", "HIGH"):
                self.block_ip(src_ip)

    def _extract_features(self, pkt, src_ip):
        """Extract numerical features for ML model."""
        return {
            "pkt_size": len(pkt),
            "protocol": 6 if pkt.haslayer(TCP) else (17 if pkt.haslayer(UDP) else 1),
            "src_port": pkt.sport if hasattr(pkt, "sport") else 0,
            "dst_port": pkt.dport if hasattr(pkt, "dport") else 0,
            "packets_per_sec": self.ip_packet_count.get(src_ip, 0),
            "unique_ports": len(self.ip_port_set.get(src_ip, set())),
            "has_payload": 1 if pkt.payload else 0,
            "tcp_flags": int(pkt[TCP].flags) if pkt.haslayer(TCP) else 0,
        }

    def _rule_based_detect(self, pkt, src_ip, dst_ip, features):
        """Fast rule-based attack signatures."""
        pps = features["packets_per_sec"]
        dst_port = features["dst_port"]

        # DDoS — high packet rate from single IP
        if pps > self.threshold:
            return self._make_alert("DDoS", src_ip, dst_ip, "HIGH", pkt, pps)

        # Port Scan — many unique ports in short time
        if pkt.haslayer(TCP):
            self.ip_port_set[src_ip].add(dst_port)
            if len(self.ip_port_set[src_ip]) > 20:
                return self._make_alert("Port Scan", src_ip, dst_ip, "MEDIUM", pkt, pps)

        # SSH Brute Force
        if dst_port == 22 and pps > 10:
            return self._make_alert("Brute Force", src_ip, dst_ip, "HIGH", pkt, pps)

        # DNS Flood
        if pkt.haslayer(DNS) and pps > 100:
            return self._make_alert("DNS Flood", src_ip, dst_ip, "CRITICAL", pkt, pps)

        # ICMP Flood
        if pkt.haslayer(ICMP) and pps > 200:
            return self._make_alert("DDoS", src_ip, dst_ip, "CRITICAL", pkt, pps)

        return None

    def _ml_detect(self, features, src_ip, dst_ip, pkt):
        """ML-based anomaly detection."""
        result = self.ml_model.predict(features)
        if result["is_attack"]:
            return self._make_alert(
                result["attack_type"], src_ip, dst_ip,
                result["severity"], pkt, features["packets_per_sec"]
            )
        return None

    def _make_alert(self, attack_type, src_ip, dst_ip, severity, pkt, pps):
        proto = "TCP" if pkt.haslayer(TCP) else ("UDP" if pkt.haslayer(UDP) else "ICMP")
        dst_port = pkt.dport if hasattr(pkt, "dport") else 0
        return {
            "type": attack_type,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "severity": severity,
            "protocol": proto,
            "port": dst_port,
            "packets": int(pps),
            "time": datetime.now().isoformat(),
        }

    # ── Background Loop ────────────────────────────────

    def _counter_reset_loop(self):
        """Reset per-IP counters every second & record traffic history."""
        while True:
            time.sleep(1)
            with self._lock:
                total_pps = sum(self.ip_packet_count.values())
                attack_pps = self.total_attacks  # rough proxy
                self.traffic_history.append({
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "packets": total_pps,
                    "attacks": min(attack_pps, total_pps),
                    "normal": max(0, total_pps - attack_pps),
                })
                self.ip_packet_count.clear()
                self.ip_port_set.clear()
