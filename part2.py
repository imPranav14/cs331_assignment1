from scapy.all import *
import sys

# Load the pcap file once
packets = rdpcap('7.pcap')

#############################################
# Test 1: Find a packet with ACK + PSH flags and
#         source port + destination port = 60303
#############################################
print("=== Test 1: ACK+PSH Flags and Port Sum ===")

def find_target_packet(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        tcp_layer = packet[TCP]
        # Check if ACK and PSH flags are set (0x10 = ACK, 0x08 = PSH)
        if tcp_layer.flags & 0x18 == 0x18:  # 0x18 is ACK (0x10) + PSH (0x08)
            # Check if the sum of source and destination ports is 60303
            if tcp_layer.sport + tcp_layer.dport == 60303:
                return True
    return False

found_test1 = False
for packet in packets:
    if find_target_packet(packet):
        ip_layer = packet[IP]
        print("Test 1 Matching Packet:")
        print(f"  Source IP: {ip_layer.src}")
        print(f"  Destination IP: {ip_layer.dst}")
        found_test1 = True
        break

if not found_test1:
    print("Test 1: No matching packet found.")

#############################################
# Test 2: Find packets with:
#         - SYN flag set,
#         - Source port divisible by 11,
#         - Sequence number > 100000
#############################################
print("\n=== Test 2: SYN Flag, Source Port Divisible by 11, and Sequence > 100000 ===")
matching_packets_count_test2 = 0

def is_target_packet_test2(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        tcp_layer = packet[TCP]
        # Check if SYN flag is set (0x02)
        if tcp_layer.flags & 0x02:
            # Check if source port is divisible by 11
            if tcp_layer.sport % 11 == 0:
                # Check if the sequence number is greater than 100000
                if tcp_layer.seq > 100000:
                    return True
    return False

for packet in packets:
    if is_target_packet_test2(packet):
        matching_packets_count_test2 += 1
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        print(f"Test 2 - Packet {matching_packets_count_test2}:")
        print(f"  Source IP: {ip_layer.src}")
        print(f"  Destination IP: {ip_layer.dst}")
        print(f"  Source Port: {tcp_layer.sport}")
        print(f"  Sequence Number: {tcp_layer.seq}")
        print("-" * 40)

print(f"Test 2: Total number of matching TCP packets: {matching_packets_count_test2}")

#############################################
# Test 3: Find packets with:
#         - Source IP starting with "18.234."
#         - Source port is a prime number
#         - Destination port divisible by 11
#############################################
print("\n=== Test 3: Source IP Pattern, Prime Source Port, and Destination Port Divisible by 11 ===")

def is_prime(n):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

matching_packets_count_test3 = 0

def is_target_packet_test3(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        # Check if the source IP starts with "18.234."
        if ip_layer.src.startswith("18.234."):
            # Check if the source port is a prime number
            if is_prime(tcp_layer.sport):
                # Check if the destination port is divisible by 11
                if tcp_layer.dport % 11 == 0:
                    return True
    return False

for packet in packets:
    if is_target_packet_test3(packet):
        matching_packets_count_test3 += 1
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        print(f"Test 3 - Packet {matching_packets_count_test3}:")
        print(f"  Source IP: {ip_layer.src}")
        print(f"  Destination IP: {ip_layer.dst}")
        print(f"  Source Port: {tcp_layer.sport}")
        print(f"  Destination Port: {tcp_layer.dport}")
        print("-" * 40)

print(f"Test 3: Total number of matching TCP packets: {matching_packets_count_test3}")

#############################################
# Test 4: Find a packet with:
#         - (Sequence Number + Acknowledgment Number) equals 2512800625
#         - The last two hex digits of the checksum equal 0x70
#############################################
print("\n=== Test 4: (Seq + Ack) Sum and Checksum Criteria ===")

def is_target_packet_test4(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        tcp_layer = packet[TCP]
        # Check if the sum of Sequence and Acknowledgment numbers equals 2512800625
        if (tcp_layer.seq + tcp_layer.ack) == 2512800625:
            # Check if the last two hex digits of the checksum are 0x70
            if (tcp_layer.chksum & 0xFF) == 0x70:
                return True
    return False

found_test4 = False
for packet in packets:
    if is_target_packet_test4(packet):
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        print("Test 4 Matching Packet Found:")
        print(f"  Source IP: {ip_layer.src}")
        print(f"  Destination IP: {ip_layer.dst}")
        print(f"  Sequence Number: {tcp_layer.seq}")
        print(f"  Acknowledgment Number: {tcp_layer.ack}")
        print(f"  Checksum (hex): 0x{tcp_layer.chksum:04x}")
        found_test4 = True
        break

if not found_test4:
    print("Test 4: No matching packet found.")
