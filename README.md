# firewall-project

## Overview

This project, developed by **Team Crypto-Vanguard**, implements a custom rate-limiting SYN proxy firewall to detect and mitigate SYN flood Denial-of-Service (DoS) attacks. The firewall monitors incoming TCP SYN packets, identifies excessive requests from specific IP addresses, and dynamically blocks malicious sources using `iptables`. An auto-unblocking mechanism ensures legitimate users are not permanently locked out, making it adaptive and efficient.

## Motivation

SYN flood attacks are a prevalent cyber threat that overwhelms servers with excessive TCP connection requests, disrupting normal operations. This project aims to provide a preventive mechanism by monitoring SYN packet rates per IP and port, setting thresholds to identify malicious behavior, and temporarily blocking offending IPs to protect server resources.

## Features

- **Real-Time Packet Sniffing**: Captures TCP packets using `Scapy` for immediate analysis.
- **SYN Flood Detection**: Tracks SYN packet rates per source IP and destination port.
- **Rate-Limiting**: Blocks IPs exceeding 5 SYN packets per second per port.
- **Dynamic IP Blocking**: Uses `iptables` to drop packets from malicious IPs.
- **Auto-Unblocking**: Unblocks IPs after a 10-minute duration to prevent false positives.
- **Multithreaded Processing**: Concurrently sniffs packets and manages unblocking tasks.
- **User-Space Implementation**: Lightweight, requiring no kernel modules.

## Architecture

The project is tested using three virtual machines in a VirtualBox NAT network:

- **Ubuntu 1 (Server)**:  
  - IP: `192.168.224.6`  
  - Hosts an Apache2 web server and runs the firewall script (`firewall.py`).
- **Ubuntu 2 (Client)**:  
  - IP: `192.168.224.7`  
  - Simulates legitimate traffic with a connectivity test script (`client_test.sh`).
- **Kali (Attacker)**:  
  - IP: `192.168.224.3`  
  - Simulates a SYN flood attack using `hping3`.

## Prerequisites

To replicate this project, ensure you have:

- **Hardware/Software**:
  - Oracle VirtualBox.
  - Ubuntu 20.04/22.04 ISOs for Server and Client VMs.
  - Kali Linux ISO for the Attacker VM.
  - Host OS (e.g., Windows, Linux, macOS) supporting VirtualBox.
- **Tools**:
  - Python 3 and `scapy` (`pip install scapy`).
  - `iptables` (pre-installed on Ubuntu).
  - Apache2 web server (`sudo apt install apache2`).
  - `curl` for client testing (`sudo apt install curl`).
  - `hping3` for attack simulation (`sudo apt install hping3`).
- **Network Setup**:
  - All VMs configured on the same VirtualBox NAT network.
  - Assigned IPs:
    - Ubuntu 1: `192.168.224.6`
    - Ubuntu 2: `192.168.224.7`
    - Kali: `192.168.224.3`

## Installation

1. **Set Up Virtual Machines**:
   - Install VirtualBox on your host machine.
   - Create three VMs:
     - **Ubuntu 1 (Server)**: Install Ubuntu, set IP to `192.168.224.6`.
     - **Ubuntu 2 (Client)**: Install Ubuntu, set IP to `192.168.224.7`.
     - **Kali (Attacker)**: Install Kali Linux, set IP to `192.168.224.3`.
   - Configure VMs to use a NAT network in VirtualBox.
   - Verify connectivity (e.g., `ping 192.168.224.6` from Kali).

2. **Install Dependencies**:
   - On **Ubuntu 1 (Server)**:
     ```bash
     sudo apt update
     sudo apt install python3 python3-pip apache2
     pip3 install scapy
     ```
   - On **Ubuntu 2 (Client)**:
     ```bash
     sudo apt update
     sudo apt install curl
     ```
   - On **Kali (Attacker)**:
     ```bash
     sudo apt update
     sudo apt install hping3
     ```

3. **Clone the Repository**:
   ```bash
   git clone https://github.com/aman181003/firewall-project.git
   cd firewall-project
   ```

## Usage

Follow these steps to run the firewall and test its functionality:

1. **Configure Ubuntu 1 (Server)**:
   - Disable UFW to avoid conflicts:
     ```bash
     sudo ufw disable
     ```
   - Set up Apache2:
     ```bash
     sudo systemctl start apache2
     sudo systemctl enable apache2
     sudo systemctl status apache2
     ```
   - Run the firewall script (requires root privileges):
     ```bash
     sudo ./firewall.py
     ```

2. **Test Connectivity from Ubuntu 2 (Client)**:
   - Copy `client_test.sh` to Ubuntu 2.
   - Make it executable and run:
     ```bash
     chmod +x client_test.sh
     sudo ./client_test.sh
     ```
   - This script continuously sends HTTP requests to `192.168.224.6`, printing "Success" or "Failed" every second.

3. **Simulate a SYN Flood Attack from Kali**:
   - Launch a SYN flood attack targeting port 80:
     ```bash
     sudo hping3 -S --flood -p 80 192.168.224.6
     ```

4. **Expected Behavior**:
   - On **Ubuntu 1 (Server)**:
     - The firewall detects SYN packets from `192.168.224.3`.
     - If the rate exceeds 5 SYN/sec, it blocks the IP and logs:
       ```
       SYN detected from 192.168.224.3 to port 80
       IP 192.168.224.3 exceeded rate limit (5 SYN/sec) on port 80, rate: X.XX SYN/sec, blocking for 10 minutes...
       Blocking IP: 192.168.224.3
       IP 192.168.224.3 will be unblocked at YYYY-MM-DD HH:MM:SS
       ```
     - After 10 minutes, it unblocks the IP:
       ```
       Unblocking IP: 192.168.224.3
       ```
   - On **Ubuntu 2 (Client)**:
     - `client_test.sh` should continue showing "Success," as legitimate traffic is unaffected.
   - On **Kali (Attacker)**:
     - Traffic is blocked during the 10-minute period, preventing the attack.

