# Network-Analysis
The Network Traffic Analysis Tool is designed to monitor and analyze live network traffic. It captures packets passing through the system’s network interface and extracts key details such as source IP, destination IP, ports, and protocols. 

from scapy.all import sniff, IP, TCP, UDP, ICMP
import csv

# csv_file = open("packet_log.csv", "w", newline="")  
csv_file = open("packet_log.csv", "w", newline="")  

# csv_writer.writerow(["Protocol", "Source IP", "Source Port", "Destination IP", "Destination Port"])  
csv_writer = csv.writer(csv_file)
csv_writer.writerow(["Protocol", "Source IP", "Source Port", "Destination IP", "Destination Port"])  

# Packet processing function
def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        
        # print(packet.summary())
        
        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif ICMP in packet:
            protocol = "ICMP"
            src_port = "-"
            dst_port = "-"
        else:
            protocol = "Other"
            src_port = "-"
            dst_port = "-"

        
        # print(packet.summary())
        
        csv_writer.writerow([protocol, src_ip, src_port, dst_ip, dst_port])
        print(f"[{protocol}] {src_ip}:{src_port} → {dst_ip}:{dst_port}")


print("Sniffing packets and saving to packet_log.csv... Press Ctrl+C to stop.")
sniff(prn=process_packet, count=50)


csv_file.close()
