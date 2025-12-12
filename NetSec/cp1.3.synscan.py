from scapy.all import *

import sys

def debug(s):
    print('#{0}'.format(s))
    sys.stdout.flush()

if __name__ == "__main__":
    conf.iface = sys.argv[1]
    ip_addr = sys.argv[2]

    my_ip = get_if_addr(sys.argv[1])

    # NOTE: print one IPAddress,port combination per line without any extra spaces
    # For example:
    # 10.4.61.4,994
    # #ignored comment line
    # 10.4.61.4,25

    for port in range(1, 1025):
        syn_pkt = IP(dst=ip_addr) / TCP(dport=port, flags='S')
        resp = sr1(syn_pkt, timeout=0.5, iface=conf.iface, verbose=0)

        if resp is not None:
            if resp.haslayer(TCP):
                if resp[TCP].flags & 0x12 == 0x12:
                    print(f"{ip_addr},{port}")
                    sys.stdout.flush()

                    rst_pkt = IP(dst=ip_addr) / TCP(dport=port, flags='R')
                    send(rst_pkt, iface=conf.iface, verbose=0)