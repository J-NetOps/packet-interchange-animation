from scapy.all import sniff

print("🕵️ Starting Raw Packet Capture for 10 seconds...")
print("⚠️ BACKGROUND LO YOUTUBE VIDEO PLAY CHEYI...")

# Yea interface peru ivvakunda, default ga edokati catch cheyamani chebuthunnam
packets = sniff(count=10, timeout=10)

print("====================================")
print(f"📦 Total Packets Captured: {len(packets)}")
print("====================================")

if len(packets) > 0:
    print("SUCCESS! Scapy is working. Here is the first packet:")
    print(packets[0].summary())
else:
    print("FAILED: Scapy is completely blind. Drivers or Firewall issue.")