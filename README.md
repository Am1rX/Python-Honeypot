# Python Honeypot 🍯

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

A simple, lightweight, and educational hybrid honeypot written in Python. This tool is designed to detect various types of network scans, including stealth scans, and to log the initial interactions from attackers.

<img width="737" height="457" alt="Screenshot 2025-09-29 231329" src="https://github.com/user-attachments/assets/36300ba3-2818-45f1-a287-ee2cd12c9907" />


---

## ✨ Features

- **Dual Detection:** Simultaneously detects full TCP connections (e.g., `nmap -sT` scans) and stealthy SYN scans (e.g., `nmap -sS` scans).
- **Fake Banners:** Serves realistic-looking banners for famous services (FTP, SSH, Telnet, HTTP, etc.) to deceive automated scanning tools.
- **Interaction Logging:** Captures and logs the first piece of data sent by an attacker after a connection is established.
- **Lightweight:** Only requires the `scapy` library for its network sniffing capabilities.
- **Readable Output:** Displays color-coded logs in the terminal for quick identification of event types.
- **Multi-threaded:** Utilizes threading to monitor all ports and sniff network traffic concurrently without blocking.

---

## ⚙️ How It Works

This honeypot consists of two main modules that run simultaneously in separate threads:

1.  **Honeypot Module:**
    - Uses Python's built-in `socket` library to listen on a defined list of ports.
    - It accepts any full TCP connection, sends the corresponding fake banner, and logs the initial interaction.

2.  **Sniffer Module:**
    - Uses the `scapy` library to sniff raw incoming traffic on the network interface.
    - It looks for TCP packets that only have the `SYN` flag set.
    - If an IP address sends a high number of SYN packets to many different ports in a short time, it identifies and flags it as a **stealth scan**.

---

## 🚀 Installation and Usage

Follow these steps to get the honeypot up and running:

**1. Clone the Repository:**
```bash
git clone https://github.com/Am1rX/Python-Honeypot.git
cd Python-Honeypot
```

**2. Install Dependencies:**
This project only requires the Scapy library.
```bash
pip install scapy
```

**3. Increase File Descriptor Limit:**
Because the script opens a large number of sockets, you must increase the open file limit in your terminal session.
```bash
ulimit -n 4096
```
Note: This command is only active for the current terminal session.

**4. Run the Script:**
This script requires root privileges to sniff network traffic and bind to ports below 1024.
```bash
sudo python3 Honey.py
```

**⚠️ Important Warning**

**For Educational & Research Purposes Only:** This is not a professional, hardened security tool for production environments.

**Run in an Isolated Environment:** Always run this honeypot on a dedicated, isolated system (like a Virtual Machine or a separate computer), not on your personal machine or a critical server.

**Legal Responsibility:** You are responsible for any data you collect with this tool. Be aware of your local privacy laws and regulations.

**🔧 Configuration**

You can easily customize the honeypot:

**PORTS_TO_MONITOR:** Edit the list of ports to monitor at the top of the script.

**BANNERS:** Modify the BANNERS dictionary to change or add new fake banners for other services.

**PORT_SCAN_THRESHOLD:** Adjust the threshold for detecting a stealth scan based on your needs.

**📄 License**

This project is licensed under the MIT License. See the LICENSE file for details.
