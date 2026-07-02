from scapy.all import sniff, IP, TCP, UDP

def process_packet(packet):
    # Packet lo IP layer unda leda ani check chesthunnam
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Simple protocol check to map to your vehicle idea
        if TCP in packet:
            proto = "Truck (TCP)"
        elif UDP in packet:
            proto = "Car (UDP)"
        else:
            proto = "Other"
            
        print(f"[{proto}] spotted from {src_ip} --> {dst_ip}")

print("Traffic Camera On! Waiting for packets...")
# Capture only 15 packets so it doesn't flood your screen
sniff(count=15, prn=process_packet)
print("Capture Complete!")