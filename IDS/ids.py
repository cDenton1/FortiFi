import sys
from datetime import datetime, timedelta
from scapy.all import *
import threading
import queue
from plyer import notification
import subprocess
import time

arp_log_list = []

def check_arp_log():
    result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
    entry = f"\n-----{datetime.now()}-----\n{result.stdout}"
    arp_log_list.append(entry)
    return arp_log_list

log_queue = queue.Queue()

iot_traffic = {"MQTT": []}  # Store timestamps of IoT traffic
IOT_THRESHOLD = 5  # Number of packets before triggering an alert
IOT_TIME_WINDOW = timedelta(seconds=30)  # Time window to track IoT traffic

class AlertSystem:
    def __init__(self, alert_log="alerts.log"):
        self.alert_log = alert_log

    def send_alert(self, message):
        print(f"ALERT: {message}")
        self.log_alert(message)

    def log_alert(self, message):
        with open(self.alert_log, "a") as log_file:
            log_file.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")


class PacketHandler(threading.Thread):
    def __init__(self, alert_system, gateway_ip, iface):
        super().__init__()
        self.alert_system = alert_system
        self.gateway_ip = gateway_ip
        self.iface = iface
        self.ssh_activity = {}
        self.arp_table = {}
        self.running = True

    def run(self):
        sniff(
            iface=self.iface,
            store=0,
            prn=self.handle_packet,
            filter="icmp or tcp or udp or arp or port 22 or port 80 or port 53 or port 1883 or port 23",
            stop_filter=lambda x: not self.running
        )

    def handle_packet(self, packet):
        is_suspicious = False

        if packet.haslayer(ICMP):
            message = f"ICMP Packet: {packet[IP].src} -> {packet[IP].dst}"
            self.alert_system.send_alert(message)
            self.log_packet("ICMP", packet)

        if packet.haslayer(ARP) and packet[ARP].op == 2:
            src_ip, src_mac = packet[ARP].psrc, packet[ARP].hwsrc
            if src_ip in self.arp_table and self.arp_table[src_ip] != src_mac:
                message = f"[!] ARP Spoofing: {src_ip} -> {src_mac}"
                self.alert_system.send_alert(message)
                self.log_packet("ARP_Spoofing", packet)
            self.arp_table[src_ip] = src_mac

        if packet.haslayer(Dot11) and packet.type == 0 and packet.subtype == 12:
            message = f"[!] Deauth Attack Detected: {packet.addr2}"
            self.alert_system.send_alert(message)
            self.log_packet("Deauth", packet)

        if packet.haslayer(TCP):
            if packet[TCP].dport in [20, 21]:
                message = f"[!] FTP Detected: {packet[IP].src} -> {packet[IP].dst}"
                self.alert_system.send_alert(message)
                self.log_packet("FTP", packet)

            if packet[TCP].dport == 22:
                if self.detect_ssh_activity(packet):
                    is_suspicious = True

            if packet[TCP].dport == 80:
                message = f"[!] HTTP Detected: {packet[IP].src} -> {packet[IP].dst}"
                self.alert_system.send_alert(message)
                self.log_packet("HTTP", packet)

            if packet[TCP].dport == 1883:
                self.track_iot_traffic("MQTT", packet)

            if packet[TCP].dport == 23:
                message = f"[!] Telnet Detected: {packet[IP].src} -> {packet[IP].dst}"
                self.alert_system.send_alert(message)
                self.log_packet("Telnet", packet)

        if packet.haslayer(UDP) and packet[UDP].dport == 53 and packet.haslayer(DNS):
            message = f"[!] DNS Query: {packet[IP].src} -> {packet[IP].dst}"
            self.alert_system.send_alert(message)
            self.log_packet("DNS", packet)

        if is_suspicious:
            self.log_packet("Suspicious", packet)

    def track_iot_traffic(self, protocol, packet):
        now = datetime.now()
        iot_traffic[protocol].append(now)
        iot_traffic[protocol] = [t for t in iot_traffic[protocol] if now - t < IOT_TIME_WINDOW]
        
        if len(iot_traffic[protocol]) > IOT_THRESHOLD:
            message = f"[!] High {protocol} Traffic Volume Detected: {len(iot_traffic[protocol])} packets in {IOT_TIME_WINDOW.seconds} seconds"
            self.alert_system.send_alert(message)
            self.log_packet(f"High_{protocol}_Traffic", packet)
            iot_traffic[protocol] = []  # Reset tracking after alert

    def log_packet(self, packet_type, packet):
        log_entry = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {packet_type}: {packet.summary()}\n"
        log_queue.put(log_entry)

    def detect_ssh_activity(self, packet):
        src_ip = packet[IP].src
        self.ssh_activity[src_ip] = self.ssh_activity.get(src_ip, 0) + 1
        if self.ssh_activity[src_ip] > 10:
            message = f"[!] SSH Brute Force: {src_ip} with {self.ssh_activity[src_ip]} attempts"
            self.alert_system.send_alert(message)
            return True
        return False
        
    def stop(self):
        self.running = False

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 ids_TRY3.py <interface> <gateway_ip>")
        sys.exit(1)
        
    check_arp_log()

    iface = sys.argv[1]
    gateway_ip = sys.argv[2]

    monitor = PacketHandler(AlertSystem(), gateway_ip, iface)
    try:
        print("Starting IDS...")
        monitor.start()
        while monitor.running:
            time.sleep(1)  # Keep the script running
    except KeyboardInterrupt:
        print("\nStopping IDS...")
        monitor.stop()
        if monitor.is_alive():
            monitor.join()  # Ensure thread stops before exiting
        sys.exit(0)
