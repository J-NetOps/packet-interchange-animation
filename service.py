import json
import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from scapy.all import sniff, Ether, IP, IPv6, TCP, UDP, conf

packet_buffer = []

class APIHandler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'X-Requested-With, Content-type')
        self.end_headers()

    def do_GET(self):
        global packet_buffer
        if self.path == '/packets':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            data_to_send = json.dumps(packet_buffer)
            packet_buffer = [] 
            self.wfile.write(data_to_send.encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass

def process_packet(packet):
    global packet_buffer
    print(".", end="", flush=True)

    is_ipv4 = packet.haslayer(IP)
    is_ipv6 = packet.haslayer(IPv6)
    if not is_ipv4 and not is_ipv6: return 

    protocol, src_port, dst_port, flags, ttl = "OTHER", "N/A", "N/A", "None", "N/A"

    if is_ipv4:
        src_ip, dst_ip, ttl = packet[IP].src, packet[IP].dst, packet[IP].ttl
        if packet[IP].proto == 1: protocol = "ICMP"
    else:
        src_ip, dst_ip = packet[IPv6].src, packet[IPv6].dst

    if packet.haslayer(TCP):
        protocol, src_port, dst_port, flags = "TCP", packet[TCP].sport, packet[TCP].dport, str(packet[TCP].flags)
    elif packet.haslayer(UDP):
        protocol, src_port, dst_port = "UDP", packet[UDP].sport, packet[UDP].dport

    src_mac = packet[Ether].src if packet.haslayer(Ether) else "Unknown"
    dst_mac = packet[Ether].dst if packet.haslayer(Ether) else "Unknown"

    packet_data = {
        "protocol": protocol, "src_ip": src_ip, "dst_ip": dst_ip,
        "src_mac": src_mac, "dst_mac": dst_mac, "src_port": src_port,
        "dst_port": dst_port, "ttl": ttl, "length": len(packet), "flags": flags
    }
    
    packet_buffer.append(packet_data)
    if len(packet_buffer) > 30: packet_buffer.pop(0)

def start_sniffer():
    print("🕵️ Auto-detecting active internet card...")
    active_card = conf.route.route("8.8.8.8")[0]
    
    # ⚠️ FIX: active_card.name badulu just active_card ani petta
    print(f"🎯 Sniper Lock! Sniffing on: {active_card}") 
    
    sniff(iface=active_card, prn=process_packet, store=False)

if __name__ == "__main__":
    threading.Thread(target=start_sniffer, daemon=True).start()
    server = ThreadingHTTPServer(('127.0.0.1', 8765), APIHandler)
    print("🚦 Server Engine Started! Open your HTML Dashboard...")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Safe Exit.")
        server.server_close()