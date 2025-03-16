import pyshark
from datetime import datetime

# File to log detected activity
LOG_FILE = "network_activity_log.txt"


# Function to log activity
def log_activity(activity):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as log_file:
        log_file.write(f"[{timestamp}] {activity}\n")


# Function to trigger alerts
def trigger_alert(alert_message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[ALERT] {timestamp} - {alert_message}")
    log_activity(f"ALERT: {alert_message}")


# Function to analyze packets
def analyze_packet(packet):
    try:
        # Extract basic info
        protocol = packet.highest_layer
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        length = int(packet.length)

        # Log general activity
        log_activity(f"Protocol: {protocol}, Source: {src_ip}, Destination: {dst_ip}, Length: {length} bytes")

        # Detect specific activity patterns
        if protocol == "HTTP":
            log_activity(f"HTTP Activity Detected: {src_ip} -> {dst_ip}")
        elif protocol == "HTTPS":
            log_activity(f"HTTPS Activity Detected: {src_ip} -> {dst_ip}")
        elif protocol == "DNS":
            log_activity(f"DNS Request: {src_ip} -> {dst_ip}")
            # Alert: Frequent DNS queries
            if hasattr(packet.dns, 'qry_name'):
                query_name = packet.dns.qry_name
                log_activity(f"DNS Query: {query_name}")
                # Trigger alert for a specific domain
                if "malicious.com" in query_name:
                    trigger_alert(f"Potentially Malicious DNS Query Detected: {query_name}")
        elif protocol == "FTP":
            log_activity(f"FTP Activity Detected: {src_ip} -> {dst_ip}")
            if hasattr(packet.ftp, 'request_command'):
                ftp_command = packet.ftp.request_command
                log_activity(f"FTP Command: {ftp_command}")
                # Trigger alert for failed login attempts
                if "USER" in ftp_command or "PASS" in ftp_command:
                    if hasattr(packet.ftp, 'response_code') and packet.ftp.response_code == "530":
                        trigger_alert(f"FTP Login Failed: {src_ip} -> {dst_ip}")
        elif protocol == "SMTP":
            log_activity(f"SMTP Activity Detected: {src_ip} -> {dst_ip}")
        elif length > 1000000:  # Example: large data transfer
            trigger_alert(f"Large Data Transfer Detected: {src_ip} -> {dst_ip} ({length} bytes)")

    except AttributeError:
        # Skip packets with missing attributes
        pass


# Function to start packet capture
def start_sniffing(source, is_file=False):
    log_activity("Starting packet capture...")
    if is_file:
        capture = pyshark.FileCapture(source)
    else:
        capture = pyshark.LiveCapture(interface=source)

    for packet in capture.sniff_continuously():
        analyze_packet(packet)


if __name__ == "__main__":
    # User selects live sniffing or file-based testing
    mode = input("Enter 'live' to capture live traffic or 'file' to analyze a .pcap file: ").strip().lower()
    if mode == "file":
        pcap_file = input("Enter the path to the .pcap file: ").strip()
        start_sniffing(pcap_file, is_file=True)
    elif mode == "live":
        network_interface = input("Enter the network interface to monitor (e.g., eth0, wlan0): ").strip()
        start_sniffing(network_interface, is_file=False)
    else:
        print("Invalid input. Please enter 'live' or 'file'.")