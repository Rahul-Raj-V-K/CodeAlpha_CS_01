from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print(f"IP Packet: {ip_src} -> {ip_dst}")

        if TCP in packet:
            tcp_src = packet[TCP].sport
            tcp_dst = packet[TCP].dport
            print(f"TCP Segment: {tcp_src} -> {tcp_dst}")

        elif UDP in packet:
            udp_src = packet[UDP].sport
            udp_dst = packet[UDP].dport
            print(f"UDP Datagram: {udp_src} -> {udp_dst}")

def start_sniffing():
    print("Starting packet capture...")
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    start_sniffing()
