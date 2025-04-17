import subprocess
import os

# === CONFIG ===
TARGET = "192.168.4.0/24"  # Your network range
NMAP_SCRIPT = "./iot-vuln-check_updated.nse"  # path to your NSE script
NMAP_PORTS = "21,22,23,80,443,554,1883,8883,1900,8000,8080,8443,8888,49152-49157,6666,6667,5353,5000"
LOG_OUTPUT = "scan_results.log"  # Save Nmap log output only

# === Step 1: Run Nmap with your custom NSE script ===
def run_nmap():
    print("[*] Running Nmap scan...")
    try:
        subprocess.run([
            "nmap",
            "-p", NMAP_PORTS,
            "--script", NMAP_SCRIPT,
            "-oN", LOG_OUTPUT,  # Save the results only to log file
            TARGET
        ], check=True)
        print("[+] Nmap scan complete.Results saved to", LOG_OUTPUT)
    except subprocess.CalledProcessError as e:
        print("[!] Nmap scan failed:", e)
        exit(1)

# === MAIN RUN ===
if __name__ == "__main__":
    run_nmap()

