#!/usr/bin/env python3
from scapy.all import *
import subprocess
from collections import defaultdict
from datetime import datetime, timedelta
import threading
import time

syn_timestamps = defaultdict(list)

RATE_LIMIT = 5  
BLOCK_DURATION = timedelta(minutes=10)  
WINDOW_SIZE = 1  

def is_ip_blocked(ip):
    """Check if the IP is already blocked in iptables."""
    result = subprocess.run(["sudo", "iptables", "-L", "-n"], stdout=subprocess.PIPE, text=True)
    return ip in result.stdout

def block_ip(ip):
    """Block the given IP using iptables."""
    if is_ip_blocked(ip):
        print(f"IP {ip} is already blocked. Skipping...")
        return
    print(f"Blocking IP: {ip}")
    try:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error blocking IP {ip}: {e}")

def unblock_ip(ip):
    """Unblock the given IP."""
    print(f"Unblocking IP: {ip}")
    try:
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error unblocking IP {ip}: {e}")

def calculate_rate(timestamps, window_size):
    """Calculate the rate of SYN packets in the given window (packets/second)."""
    now = datetime.now()
    recent = [t for t in timestamps if (now - t).total_seconds() <= window_size]
    timestamps[:] = recent
    return len(recent) / window_size if recent else 0

def handle_packet(packet):
    if TCP in packet and packet[TCP].flags == "S":  
        src_ip = packet[IP].src
        target_port = packet[TCP].dport
        current_time = datetime.now()

        print(f"SYN detected from {src_ip} to port {target_port}")

        key = (src_ip, target_port)

        syn_timestamps[key].append(current_time)

        rate = calculate_rate(syn_timestamps[key], WINDOW_SIZE)

        if rate > RATE_LIMIT:
            print(f"IP {src_ip} exceeded rate limit ({RATE_LIMIT} SYN/sec) on port {target_port}, rate: {rate:.2f} SYN/sec, blocking for {BLOCK_DURATION.seconds//60} minutes...")
            block_ip(src_ip)
            unblock_time = current_time + BLOCK_DURATION
            print(f"IP {src_ip} will be unblocked at {unblock_time.strftime('%Y-%m-%d %H:%M:%S')}")
            sniff_thread.unblock_tasks.append({"ip": src_ip, "unblock_time": unblock_time})
            return

def unblock_expired_ips():
    """Unblock IPs whose block duration has expired."""
    now = datetime.now()
    for task in list(sniff_thread.unblock_tasks):
        if now >= task["unblock_time"]:
            unblock_ip(task["ip"])
            src_ip = task["ip"]
            for key in list(syn_timestamps.keys()):
                if key[0] == src_ip:
                    del syn_timestamps[key]
            sniff_thread.unblock_tasks.remove(task)

class SniffThread:
    def __init__(self):  
        self.unblock_tasks = []

    def start_sniffing(self):
        sniff(filter="tcp", prn=handle_packet,iface="enp0s3")

if __name__ == "__main__":
    print("Starting firewall...")  
    sniff_thread = SniffThread()
    sniff_thread_thread = threading.Thread(target=sniff_thread.start_sniffing, daemon=True)
    sniff_thread_thread.start()

    try:
        while True:
            unblock_expired_ips()
            time.sleep(1)  
    except KeyboardInterrupt:
        print("\nStopping...")