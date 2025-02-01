from scapy.all import sniff, IP, TCP, UDP, ICMP

# Global variables to store statistics
total_packets = 0
total_bytes = 0
packet_sizes = []
unique_pairs = set()  # Set to store unique (src_ip:port -> dst_ip:port) pairs

def packet_callback(packet):
    global total_packets, total_bytes, packet_sizes, unique_pairs

    # Get packet size
    packet_size = len(packet)
    total_packets += 1
    total_bytes += packet_size
    packet_sizes.append(packet_size)

    # Extract source and destination details
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = "N/A"
        dst_port = "N/A"

        # Check if packet contains TCP or UDP (to extract port numbers)
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif ICMP in packet:
            src_port = "ICMP"
            dst_port = "ICMP"

        # Store unique pairs
        unique_pairs.add((src_ip, src_port, dst_ip, dst_port))

# Capture packets from the loopback interface during replay
print("Sniffing packets on lo0 interface...")
sniff(iface="lo0", prn=packet_callback, store=False, timeout=30)

# Compute statistics
min_size = min(packet_sizes) if packet_sizes else 0
max_size = max(packet_sizes) if packet_sizes else 0
avg_size = (total_bytes / total_packets) if total_packets > 0 else 0

# Display packet statistics
print("\n--- Packet Statistics ---")
print(f"Total Packets Transferred: {total_packets}")
print(f"Total Data Transferred: {total_bytes} bytes")
print(f"Min Packet Size: {min_size} bytes")
print(f"Max Packet Size: {max_size} bytes")
print(f"Average Packet Size: {avg_size:.2f} bytes")

# Print only the total number of unique source-destination pairs
print(f"\nTotal Unique Source-Destination Pairs Found: {len(unique_pairs)}")
