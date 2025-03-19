# this tests port 80, 21, 22 UDP DNS, and ARP
# to test MQTT run a command like: mosquitto_pub -h [target ip] -t "test/topic" -m "Hello, MQTT"

from scapy.all import *
import time
import threading

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

def send_arp_spoof(target, fake_mac):
    print("[+] Sending ARP spoof packet")
    for _ in range(5):
        send(ARP(op=2, psrc=target, hwsrc=fake_mac), verbose=False)
        time.sleep(1)

def start_attack(target_ip, gateway_ip):
    threads = [
        threading.Thread(target=send_icmp, args=(target_ip,)),
        threading.Thread(target=send_tcp, args=(target_ip, 80)),  # HTTP
        threading.Thread(target=send_tcp, args=(target_ip, 21)),  # FTP
        threading.Thread(target=send_tcp, args=(target_ip, 22)),  # SSH
        threading.Thread(target=send_udp_dns, args=(target_ip,)),
        threading.Thread(target=send_arp_spoof, args=(gateway_ip, "00:11:22:33:44:55"))
    ]
    
    for t in threads:
        t.start()
    
    for t in threads:
        t.join()

if __name__ == "__main__":
    target_ip = input("Enter target IP: ")
    gateway_ip = input("Enter gateway IP: ")
    start_attack(target_ip, gateway_ip)
