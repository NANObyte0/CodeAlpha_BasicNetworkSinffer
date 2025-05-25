from scapy.all import sniff, wrpcap
from scapy.layers.inet import IP

# List to store captured packets
packets = []

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        protocol = ip_layer.proto
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # Determine the protocol
        protocol_name = ""
        if protocol == 1:
            protocol_name = "ICMP"
        elif protocol == 6:
            protocol_name = "TCP"
        elif protocol == 17:
            protocol_name = "UDP"
        else:
            protocol_name = "Unknown Protocol"

        # Print packet details
        print(f"Protocol: {protocol_name}")
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print("_" * 50)

        # Store the packet
        packets.append(packet)

def main():
    try:
        print("[*] Starting packet sniffing... Press CTRL+C to stop.")
        sniff(prn=packet_callback, filter="ip", store=0)
    except KeyboardInterrupt:
        print("\n[*] Saving captured packets to file...")
        wrpcap("captured_packets.pcap", packets)
        print("[*] Packets saved to captured_packets.pcap")

if __name__ == "__main__":
    main()
