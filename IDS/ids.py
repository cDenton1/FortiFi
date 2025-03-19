import sys
from datetime import datetime
from scapy.all import *
import threading
import queue
from plyer import notification
import getpass
import subprocess

arp_log_list = []

def check_arp_log():
    result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
    entry = f"\n-----{datetime.now()}-----\n{result.stdout}"
    arp_log_list.append(entry)
    return arp_log_list

log_queue = queue.Queue()

class AlertSystem:
    def __init__(self, alert_log="alerts.log"):
        self.alert_log = alert_log

    def send_alert(self, message):
        print(f"ALERT: {message}")
        self.log_alert(message)
        self.show_os_notification(message)

    def log_alert(self, message):
        with open(self.alert_log, "a") as log_file:
            log_file.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")

    def show_os_notification(self, message):
        notification.notify(
            title="Network Alert",
            message=message,
            timeout=5
        )

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
                message = f"[!] MQTT Traffic: {packet[IP].src} -> {packet[IP].dst}"
                self.alert_system.send_alert(message)
                self.log_packet("MQTT", packet)

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

    iface = sys.argv[1]
    gateway_ip = sys.argv[2]

    monitor = PacketHandler(AlertSystem(), gateway_ip, iface)
    try:
        print("Starting IDS...")
        monitor.start()
        while True:
            time.sleep(1)  # Keep the script running
    except KeyboardInterrupt:
        print("\nStopping IDS...")
        monitor.stop()
        monitor.join()  # Ensure thread stops before exiting
        sys.exit(0)
