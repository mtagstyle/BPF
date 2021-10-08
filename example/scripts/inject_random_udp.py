import time
import random
import socket
import struct

from scapy.all import IP, Ether, UDP, Raw
from scapy.sendrecv import sendp

BROADCAST_MAC_ADDR="ff:ff:ff:ff:ff:ff"

if __name__ == "__main__":
    egress_name = "bpf_veth_out"
    ingress_name = "bpf_veth_in"
    max_ips = 0x5

    # Periodically generates a UDP packet with a random source IPv4 address to be inserted in the LRU cache.
    while True:
        sendp(Ether(dst=BROADCAST_MAC_ADDR)/IP(src=socket.inet_ntoa(struct.pack('>I', random.randint(1, max_ips))), dst="1.2.3.4")/UDP(dport=8888)/Raw(load="Hello World From Scapy Ingress"), iface=ingress_name)
        sendp(Ether(dst=BROADCAST_MAC_ADDR)/IP(src=socket.inet_ntoa(struct.pack('>I', random.randint(1, max_ips))),dst="4.3.2.1")/UDP(dport=8888)/Raw(load="Hello World From Scapy Egress"), iface=egress_name)
        time.sleep(5)