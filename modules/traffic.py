import requests
import subprocess
import time
import threading

# Popular websites for normal traffic generation
TARGETS = [
    "google.com",
    "wikipedia.org",
    "github.com",
    "stackoverflow.com",
    "microsoft.com"
]

def http_gen():
    """Generate HTTP/HTTPS requests"""
    while True:
        for target in TARGETS:
            try:
                requests.get(f"https://{target}", timeout=3)
                requests.get(f"http://{target}", timeout=3)
            except:
                pass
        time.sleep(0.5)

def ping_gen():
    """Generate ICMP ping traffic"""
    while True:
        for target in TARGETS:
            subprocess.run(['ping', '-n', '2', target], 
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)

def dns_gen():
    """Generate DNS lookups"""
    while True:
        for target in TARGETS:
            subprocess.run(['nslookup', target], 
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)

# Start multiple threads for each generator
for func in [http_gen, ping_gen, dns_gen]:
    for _ in range(3):  # 3 threads per type = 9 total threads
        threading.Thread(target=func, daemon=True).start()

print("="*60)
print(" NORMAL TRAFFIC GENERATOR - Running")
print("="*60)
print(f"\nGenerating traffic to: {', '.join(TARGETS)}")
print("\n[*] HTTP/HTTPS requests, pings, and DNS lookups active")
print("[*] Press Ctrl+C to stop...")
print("-"*60)

try:
    while True:
        time.sleep(2)
        print(".", end="", flush=True)
except KeyboardInterrupt:
    print("\n\n[!] Generator stopped")
