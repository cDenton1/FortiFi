import sys
import os
import subprocess
from datetime import datetime, timedelta
from scapy.all import *
import threading
import queue
from plyer import notification
import time

arp_log_list = []

def check_arp_log():
    result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
    entry = f"\n-----{datetime.now()}-----\n{result.stdout}"
    arp_log_list.append(entry)
    return arp_log_list

log_queue = queue.Queue()

iot_traffic = {"MQTT": [], "MQTT_TLS": []} # Store timestamps of IoT traffic
IOT_THRESHOLD = 1  # Number of packets before triggering an alert
IOT_TIME_WINDOW = timedelta(seconds=10)  # Time window to track IoT traffic

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
            filter="icmp or tcp or udp or arp or port 22 or port 80 or port 53 or port 1883 or port 8883 or port 23 or port 443",
            stop_filter=self.stop_filter
        )

    def handle_packet(self, packet):
        is_suspicious = False

        if packet.haslayer(ICMP):
            severity = "Low"
            message = f"[{severity}] ICMP Packet: {packet[IP].src} -> {packet[IP].dst}"
            self.alert_system.send_alert(message)
            self.log_packet("ICMP", severity, packet)

        if packet.haslayer(ARP) and packet[ARP].op == 2:
            severity = "High"
            src_ip, src_mac = packet[ARP].psrc, packet[ARP].hwsrc
            if src_ip in self.arp_table and self.arp_table[src_ip] != src_mac:
                message = f"[{severity}] ARP Spoofing: {src_ip} -> {src_mac}"
                self.alert_system.send_alert(message)
                self.log_packet("ARP_Spoofing", severity, packet)
            self.arp_table[src_ip] = src_mac

        if packet.haslayer(Dot11) and packet.type == 0 and packet.subtype == 12:
            severity = "High"
            message = f"[{severity}] Deauth Attack Detected: {packet.addr2}"
            self.alert_system.send_alert(message)
            self.log_packet("Deauth", severity, packet)

        if packet.haslayer(TCP):
            if packet[TCP].dport in [20, 21]:
                severity = "Medium"
                message = f"[{severity}] FTP Detected: {packet[IP].src} -> {packet[IP].dst}"
                self.alert_system.send_alert(message)
                self.log_packet("FTP", severity, packet)

            if packet[TCP].dport == 22:
                if self.detect_ssh_activity(packet):
                    severity = "High"
                    is_suspicious = True

            if packet[TCP].dport == 80:
                severity = "Medium"
                message = f"[{severity}] HTTP Detected: {packet[IP].src} -> {packet[IP].dst}"
                self.alert_system.send_alert(message)
                self.log_packet("HTTP", severity, packet)
                
            if packet[TCP].dport == 443:
                severity = "Low"
                message = f"[{severity}] HTTPS Detected: {packet[IP].src} -> {packet[IP].dst}"
                self.alert_system.send_alert(message)
                self.log_packet("HTTPS", severity, packet)

            if packet[TCP].dport == 1883:
                self.track_iot_traffic("MQTT", packet)
            if packet[TCP].dport == 8883:
                self.track_iot_traffic("MQTT_TLS", packet)

            if packet[TCP].dport == 23:
                severity = "Low"
                message = f"[{severity}] Telnet Detected: {packet[IP].src} -> {packet[IP].dst}"
                self.alert_system.send_alert(message)
                self.log_packet("Telnet", severity, packet)

        if packet.haslayer(UDP) and packet[UDP].dport == 53 and packet.haslayer(DNS):
            src_ip = "{packet{IP}.src}"
            
            if src_ip not in self.arp_table:
                severity = "High"
                message = f"[{severity}] Suspicious DNS Query: {packet[IP].src}"
            else:
                severity = "Low"
                message = f"[{severity}] DNS Query: {packet[IP].src} -> {packet[IP].dst}"
                
            self.alert_system.send_alert(message)
            self.log_packet("DNS", severity, packet)

        if is_suspicious:
            self.log_packet("Suspicious", "High", packet)

    def log_tls_handshake(self, packet):
        if Raw in packet:
            data = bytes(packet[Raw].load)
    
            if data.startswith(b'\x16\x03'):  # TLS record
                handshake_type = data[5]
    
                if handshake_type == 0x01:
                    self.alert_system.send_alert("[Low] TLS Client Hello Detected")
                    self.log_packet("TLS_Client_Hello", "Low", packet)
                elif handshake_type == 0x02:
                    self.alert_system.send_alert("[Low] TLS Server Hello Detected")
                    self.log_packet("TLS_Server_Hello", "Low", packet)
                elif handshake_type == 0x0b:
                    self.alert_system.send_alert("[Medium] TLS Certificate Sent")
                    self.log_packet("TLS_Certificate", "Medium", packet)
    
    def track_iot_traffic(self, protocol, packet):
        now = datetime.now()
        iot_traffic[protocol].append(now)

        # Clean up old packets outside the time window
        iot_traffic[protocol] = [t for t in iot_traffic[protocol] if now - t < IOT_TIME_WINDOW]

        # Get the number of packets received in the time window
        packet_count = len(iot_traffic[protocol])
        
        # Print the packet count for debugging purposes
        # print(f"MQTT packets received: {packet_count} in the last {IOT_TIME_WINDOW.seconds} seconds")

        # Only trigger the alert if the count crosses the threshold
        if packet_count >= 15:
            severity = "High"
            message = f"[{severity}] {protocol} Traffic Volume Detected: {packet_count} packets in {IOT_TIME_WINDOW.seconds} seconds"
            self.alert_system.send_alert(message)
            self.log_packet(f"{severity}_{protocol}_Traffic", severity, packet)
            iot_traffic[protocol] = []  # Reset the packet tracking after the alert
            
        elif packet_count >= 5:
            severity = "Medium"
            message = f"[{severity}] {protocol} Traffic Volume Detected: {packet_count} packets in {IOT_TIME_WINDOW.seconds} seconds"
            self.alert_system.send_alert(message)
            self.log_packet(f"{severity}_{protocol}_Traffic", severity, packet)
            iot_traffic[protocol] = []  # Reset the packet tracking after the alert
            
        # elif packet_count > 0:
            # Print out traffic below threshold for debugging
            # print(f"Low level {protocol} traffic detected but not enough to alert.")

    def log_packet(self, packet_type, severity, packet):
        log_entry = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {severity} {packet_type}: {packet.summary()}\n"
        log_queue.put(log_entry)

    def detect_ssh_activity(self, packet):
        src_ip = packet[IP].src
        self.ssh_activity[src_ip] = self.ssh_activity.get(src_ip, 0) + 1
        if self.ssh_activity[src_ip] > 10:
            severity = "High"
            message = f"[{severity}] SSH Brute Force: {src_ip} with {self.ssh_activity[src_ip]} attempts"
            self.alert_system.send_alert(message)
            return True
        return False

    def stop_filter(self, packet):
        return not self.running

    def stop(self):
        self.running = False


def get_gateway_ip():
    try:
        result = subprocess.run(['ip', 'route', 'show'], capture_output=True, text=True)
        gateway_ip = None
        for line in result.stdout.splitlines():
            if 'default' in line:
                gateway_ip = line.split()[2]  # Gateway IP is usually in the third column
                break
        return gateway_ip
    except Exception as e:
        print(f"Error fetching gateway IP: {e}")
        return None


def get_network_interface():
    try:
        result = subprocess.run(['ip', 'a'], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if 'state UP' in line:
                interface = line.split(":")[1].strip()
                return interface
        return None
    except Exception as e:
        print(f"Error fetching network interface: {e}")
        return None

if __name__ == "__main__":
    gateway_ip = get_gateway_ip()
    iface = "wlan0"

    if not gateway_ip or not iface:
        print("Error: Could not automatically detect the gateway IP or network interface.")
        sys.exit(1)

    check_arp_log()

    print(f"Using gateway IP: {gateway_ip}")
    print(f"Using network interface: {iface}")

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
