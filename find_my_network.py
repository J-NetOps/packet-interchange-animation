from scapy.all import sniff

# Nuvvu pampina list of interfaces
interfaces = [
    r'\Device\NPF_{5E139B8F-0924-4A03-A5EB-986DE12E28EF}',
    r'\Device\NPF_{A23C03F6-F3F4-4B1D-A605-CDCF22C3EC54}',
    r'\Device\NPF_{A058F540-C0AB-4953-A8D3-1041111658E5}',
    r'\Device\NPF_{3B562621-ECD7-4206-9BA4-7E0C4988417A}'
]

print("🕵️ Starting Auto-Discovery for Active Network Card...")
print("IMPORTANT: Please start playing a YouTube video or ping 8.8.8.8 in the background!\n")

active_iface = None

for iface in interfaces:
    print(f"⏳ Testing interface: {iface}")
    try:
        # Prathi interface paina 3 seconds wait chesthundi packet kosam
        packets = sniff(iface=iface, count=1, timeout=3)
        if len(packets) > 0:
            print(f"✅ BINGO! Traffic detected!\n")
            active_iface = iface
            break
        else:
            print("❌ No traffic here. Moving to next...\n")
    except Exception as e:
        print(f"⚠️ Error on this interface. Skipping...\n")

if active_iface:
    print("==================================================")
    print("🎉 SUCCESS! Nee active network card dorikindi!")
    print("Nee live_engine.py lo sniffer line ni ikkada unnatlu exact ga replace chey:")
    print(f'sniffer = AsyncSniffer(iface=r"{active_iface}", prn=process_packet, store=False)')
    print("==================================================")
else:
    print("💀 No traffic found on ANY interface. Internet active ga undo ledo check chey.")