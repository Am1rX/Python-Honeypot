import socket
import threading
from datetime import datetime
import scapy.all as scapy
from collections import defaultdict
import time

# --- Global Configuration ---
HOST = '0.0.0.0'
PORTS_TO_MONITOR = range(1, 1025)
LOG_FILE = 'honeypot_log.txt'
TIME_WINDOW = 10  # Seconds
PORT_SCAN_THRESHOLD = 15 # SYN packets to trigger alert

# --- Fake Banners for Common Services ---
BANNERS = {
    # --- File Transfer & Remote Access ---
    21: b'220 ProFTPD 1.3.5 Server (Debian) [::ffff:127.0.0.1]\r\n',
    22: b'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1\r\n',
    23: b'Debian GNU/Linux 10\r\nKernel 4.19.0-13-amd64 on an x86_64\r\nlogin: ',
    
    # --- Mail Services ---
    25: b'220 mail.example.com ESMTP Postfix\r\n',
    110: b'+OK POP3 server ready <1896.697170952@dbc.mtview.ca.us>\r\n',
    143: b'* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE] Dovecot ready.\r\n',

    # --- Web Services ---
    80: b'HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n',
    443: b'', # HTTPS/SSL does not send a clear-text banner. Just listening is enough.

    # --- Windows & Samba Services ---
    135: b'', # MSRPC - Complex binary protocol.
    139: b'', # NetBIOS Session Service - Complex.
    445: b'\x00\x00\x00\x00', # SMB - A minimal, non-functional response to log the attempt.

    # --- Database Services ---
    3306: b'\x5a\x00\x00\x00\x0a\x35\x2e\x35\x2e\x35\x2d\x31\x30\x2e\x34\x2e\x31\x31\x2d\x4d\x61\x72\x69\x61\x44\x42\x00\x01\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', # MySQL handshake packet

    # --- Remote Desktop & VNC ---
    3389: b'', # RDP - Complex binary protocol. Listening is enough.
    5900: b'RFB 003.008\n', # VNC Protocol

    # --- Other Common Services ---
    53: b'', # DNS - Complex protocol.
    8080: b'HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n' # Common HTTP alternate port
}

# --- Shared Resources ---
console_lock = threading.Lock()
detected_scanners = defaultdict(lambda: {'timestamp': time.time(), 'ports': set()})

# --- Color Class for Console Output ---
class Colors:
    RESET = '\033[0m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    RED_BG = '\033[41m'

# ==============================================================================
# SECTION 1: TCP CONNECT HONEYPOT (Handles full connections)
# ==============================================================================

def log_event(attacker_ip, port, data=None):
    """Logs connections and interactions to both console and file."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    with console_lock:
        # --- Console Logging ---
        log_type = "Interaction" if data else "Connection"
        log_color = Colors.MAGENTA if data else Colors.CYAN
        
        log_message_console = (
            f"[{Colors.GREEN}{timestamp}{Colors.RESET}] "
            f"{log_color}{log_type} Detected!{Colors.RESET} "
            f"Source: {Colors.YELLOW}{attacker_ip}{Colors.RESET} "
            f"on Port: {Colors.RED}{port}{Colors.RESET}"
        )
        print(log_message_console)
        
        # --- File Logging ---
        log_message_file = f"[{timestamp}] [{log_type}] Source: {attacker_ip} Port: {port}"
        if data:
            # repr() makes the data safe for logging and printing
            safe_data = repr(data)
            print(f"    {Colors.MAGENTA}>> Data Received:{Colors.RESET} {safe_data}")
            log_message_file += f" Data: {safe_data}\n"
        else:
            log_message_file += "\n"

        with open(LOG_FILE, 'a') as f:
            f.write(log_message_file)

def handle_connection(port):
    """Listens, sends a banner, receives data, and logs the event."""
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, port))
        server_socket.listen(5)
        while True:
            client_socket, addr = server_socket.accept()
            attacker_ip = addr[0]
            data = None
            
            try:
                # Send the banner
                banner = BANNERS.get(port)
                if banner:
                    client_socket.send(banner)
                
                # Set a timeout and wait for data
                client_socket.settimeout(5.0)
                data = client_socket.recv(1024)
                
            except socket.timeout:
                # This is normal, it means the client connected but sent no data
                pass
            except Exception:
                pass # Ignore other potential errors
            finally:
                # Log the event, whether data was received or not
                log_event(attacker_ip, port, data)
                client_socket.close()
    except Exception:
        # This will catch errors like "Permission Denied" if not run with sudo,
        # or "Address already in use" for specific ports.
        pass

def run_honeypot():
    """Starts a thread for each port to be monitored."""
    with console_lock:
        print(f"[+] Honeypot Module: Monitoring {len(list(PORTS_TO_MONITOR))} ports for full connections.")
    for port in PORTS_TO_MONITOR:
        thread = threading.Thread(target=handle_connection, args=(port,))
        thread.daemon = True
        thread.start()

# ==============================================================================
# SECTION 2: SYN SCAN DETECTOR (Sniffs for stealth scans)
# ==============================================================================

def packet_handler(packet):
    """Callback function for the sniffer to process each packet."""
    if packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == 'S':
        attacker_ip = packet[scapy.IP].src
        dest_port = packet[scapy.TCP].dport
        current_time = time.time()

        if current_time - detected_scanners[attacker_ip]['timestamp'] > TIME_WINDOW:
            detected_scanners[attacker_ip] = {'timestamp': current_time, 'ports': {dest_port}}
        else:
            detected_scanners[attacker_ip]['ports'].add(dest_port)

        scanned_ports_count = len(detected_scanners[attacker_ip]['ports'])
        
        if scanned_ports_count > PORT_SCAN_THRESHOLD:
            ports = sorted(list(detected_scanners[attacker_ip]['ports']))
            alert_message = (
                f"\n{Colors.RED_BG} !!! STEALTH SCAN DETECTED !!! {Colors.RESET}\n"
                f"Source IP: {Colors.YELLOW}{attacker_ip}{Colors.RESET}\n"
                f"Ports Scanned ({scanned_ports_count}): {str(ports)[:100]}...\n"
            )
            with console_lock:
                print(alert_message)
            del detected_scanners[attacker_ip]

def run_sniffer():
    """Starts the Scapy network sniffer."""
    with console_lock:
        print(f"[+] Sniffer Module: Listening for stealthy SYN scans.")
    try:
        scapy.sniff(filter="tcp", prn=packet_handler, store=0)
    except PermissionError:
        with console_lock:
            print(f"{Colors.RED}[-] Sniffer Error: Permission denied. Please run with sudo.{Colors.RESET}")
    except Exception as e:
        with console_lock:
            print(f"[-] Sniffer Error: {e}")
            
# ==============================================================================
# MAIN EXECUTION
# ==============================================================================
if __name__ == '__main__':
    print("[+] Starting Hybrid Honeypot...")
    
    # Don't forget to increase the file descriptor limit if monitoring many ports!
    # In your terminal, run: ulimit -n 4096

    honeypot_thread = threading.Thread(target=run_honeypot)
    honeypot_thread.daemon = True
    honeypot_thread.start()

    sniffer_thread = threading.Thread(target=run_sniffer)
    sniffer_thread.daemon = True
    sniffer_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{Colors.GREEN}[+] Shutting down Hybrid Honeypot.{Colors.RESET}")
