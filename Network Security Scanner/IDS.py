import os
import argparse
import logging
from datetime import datetime, timedelta
from scapy.all import sniff, Raw, TCP, IP

# -- Setup logging --
log_filename = 'logs/{}.log'.format(datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
os.makedirs('logs', exist_ok=True) # Ensure logs directory exists
logging.basicConfig(filename=log_filename, level=logging.INFO, format='%(asctime)s - %(message)s')
alert_count = 1

#############################################################################
# alert
# Prints an alert message and logs it with a unique ID
# Requires: A string message msg
# Result: None
# State Changes: Increments global alert_count writes to stdout and log file
#############################################################################
def alert(msg):
    global alert_count
    print(f"ALERT #{alert_count}: {msg}")
    logging.info(f"ALERT #{alert_count}: {msg}")
    alert_count += 1

# Stores {src_ip: {'syn_count': int, 'last_seen': datetime}}
syn_scan_tracker = {}
SYN_THRESHOLD = 10 # Number of SYN packets to consider it a potential scan
SYN_WINDOW_SECONDS = 5 # Time window in seconds

##########################################################################
# detect_stealth_scan
# Detects common stealth scans NULL, FIN, XMAS, SYN
# Requires: A scapy packet with TCP/IP layers
# Result: None
# State Changes: Calls alert if suspicious TCP flags detected
#                Tracks SYN packet frequency using global syn_scan_tracker
##########################################################################
def detect_stealth_scan(pkt):
    global syn_scan_tracker

    if pkt.haslayer(TCP):
        flags_int = pkt[TCP].flags
        src = pkt[IP].src

        # Existing NULL, FIN, XMAS detections (these are usually less noisy)
        if flags_int == 0:
            alert(f"NULL scan detected from {src}")
        elif flags_int == 1:
            alert(f"FIN scan detected from {src}")
        elif flags_int == 41:
            alert(f"XMAS scan detected from {src}")
        # SYN scan detection with simple rate limiting
        elif flags_int == 2: # SYN flag
            now = datetime.now()
            if src not in syn_scan_tracker:
                syn_scan_tracker[src] = {'syn_count': 1, 'last_seen': now}
            else:
                # If outside the window, reset count and update time
                if now - syn_scan_tracker[src]['last_seen'] > timedelta(seconds=SYN_WINDOW_SECONDS):
                    syn_scan_tracker[src]['syn_count'] = 1
                    syn_scan_tracker[src]['last_seen'] = now
                else:
                    syn_scan_tracker[src]['syn_count'] += 1

                # If threshold exceeded, alert and reset count to avoid re-alerting immediately
                if syn_scan_tracker[src]['syn_count'] >= SYN_THRESHOLD:
                    alert(f"High rate of SYN packets detected from {src} ({syn_scan_tracker[src]['syn_count']} SYNs in {SYN_WINDOW_SECONDS}s). Possible SYN scan.")
                    # Optionally reset count to avoid continuous alerts for the same scan
                    syn_scan_tracker[src]['syn_count'] = 0 # Reset or set to 1 to count after initial alert

########################################################################
# detect_nikto
# Detects Nikto scanner by matching "Nikto" keyword in payload
# Requires: A scapy packet with IP and Raw layers
# Result: None
# State Changes: Calls alert if Nikto signature is present.
########################################################################
def detect_nikto(pkt):
    if pkt.haslayer(Raw) and b"Nikto" in pkt[Raw].load:
        src = pkt[IP].src
        alert(f"Nikto scan detected from {src}")

########################################################################
# detect_shellshock
# Detects Shellshock Bash vulnerability exploit attempts via payload pattern
# Requires: A scapy packet with Raw layer
# Result: None
# State Changes: Calls alert if Shellshock pattern "() {" and "; };" found
########################################################################
def detect_shellshock(pkt):
    if pkt.haslayer(Raw):
        payload = pkt[Raw].load.decode(errors="ignore")
        if "() {" in payload and "; };" in payload:
            src = pkt[IP].src
            alert(f"Shellshock pattern detected from {src}")

########################################################################
# packhandler
# Main handler function for incoming packets
# Requires: A scapy packet any type expected to have IP layer
# Result: None
# State Changes: Calls detection functions: detect_stealth_scan,
#                detect_nikto, and detect_shellshock
########################################################################
def packhandler(pkt):
    # print("DEBUG: Process called for a packet.")
    if pkt.haslayer(IP):
        # print(f"DEBUG: Packet has IP layer from {pkt[IP].src}")
        detect_stealth_scan(pkt)
        detect_nikto(pkt)
        detect_shellshock(pkt)
    # else:
    #     print("DEBUG: Packet does NOT have IP layer.")

# -- Main CLI --
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detects stealth scans, Nikto scans and Shellshock injection attacks from a .pcapng or live traffic")
    parser.add_argument("-L", dest="live", help="Sniff LIVE from the CLI, Example: IDS.py -L [Network Name]")
    parser.add_argument("-r", dest="pcap", help="Reads from a .pcapng file")
    args = parser.parse_args()

    print("Starting network analysis...\n")
    logging.info("Network analysis started.")
    if args.pcap:
        sniff(offline=args.pcap, prn=packhandler, store=0)
    elif args.live:
        sniff(iface=args.live, prn=packhandler, store=0)
    else:
        parser.print_help()
    logging.info("Network analysis finished.")