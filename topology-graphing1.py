import os
os.sys.path.append('/usr/local/lib/python3/site-packages')

#!/usr/bin/python

import sys
import networkx as nx
import ipaddress
import matplotlib.pyplot as plt
from scapy.all import *

def trace_route(host, graph):
    print("Traceroute " + host)

    ttl = 1

    while ttl <= 30:
        IPLayer = IP()
        IPLayer.dst = host
        IPLayer.ttl = ttl
        ICMPpkt = ICMP()
        pkt = IPLayer/ICMPpkt
        replypkt = sr1(pkt, verbose=0, timeout=5)

        if replypkt is None:
            break
        elif replypkt[ICMP].type == 0:
            print("%d hops away: " % ttl, replypkt[IP].src)
            graph.add_node(replypkt[IP].src)
            break
        else:
            print("%d hops away: " % ttl, replypkt[IP].src)
            graph.add_node(replypkt[IP].src)
            if ttl > 1:
                graph.add_edge(prev_ip, replypkt[IP].src)
            prev_ip = replypkt[IP].src
            ttl += 1

def generate_ips(start_ip, end_ip, skip=1):
    start = ipaddress.IPv4Address(start_ip)
    end = ipaddress.IPv4Address(end_ip)
    ips = []

    current = start
    while current <= end:
        ips.append(str(current))
        current += skip

    return ips

if __name__ == '__main__':
    graph = nx.Graph()
    #public_ip_range = generate_ips("138.238.0.0", "138.238.0.255", skip=8)
    public_ip_range = generate_ips("10.255.255.0", "10.255.255.255", skip=8)
    for ip in public_ip_range:
        trace_route(ip, graph)

    # Draw and display the network graph
    pos = nx.spring_layout(graph)  # You can change the layout as needed
    nx.draw(graph, pos, with_labels=True, node_size=500, node_color='skyblue', font_size=8)
    plt.title("Network Topology")
    plt.show()

"""

The address space of the public IP is from 138.238.0.0 to 138.238.255.255.

The address space of the private P is from 10.0.0.0 to 10.255.255.255.

You can skip some numbers for the last number in the IP address. For example, 
138.238.0.1, then 138.238.0.8, 138.238.0.16 and so on. But I would not recommend 
skipping the second or third number in the IP addresses.

"""
