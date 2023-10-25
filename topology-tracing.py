import sys
import os
import ipaddress
from scapy.all import *
import threading
import json

def trace_route(host, results):
    print("Traceroute " + host)

    ttl = 1

    # anything past 6th hop is beyond howard's network
    while ttl <= 6:
        IPLayer = IP()
        IPLayer.dst = host
        IPLayer.ttl = ttl
        ICMPpkt = ICMP()
        pkt = IPLayer / ICMPpkt
        replypkt = sr1(pkt, verbose=0, timeout=5)

        if replypkt is None:
            break
        elif replypkt[ICMP].type == 0:
            print("%d hops away: " % ttl, replypkt[IP].src)
            # store hop, ip address for graphing
            result = {
                "hop": ttl,
                "ip": replypkt[IP].src
            }
            results[host].append(result)
            break
        else:
            print("%d hops away: " % ttl, replypkt[IP].src)
            result = {
                "hop": ttl,
                "ip": replypkt[IP].src
            }
            results[host].append(result)
            ttl += 1


# multithreading
def trace_route_with_threads(ip_range, results):
    threads = []

    for ip in ip_range:
        results[ip] = []
        thread = threading.Thread(target=trace_route, args=(ip, results))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()


# generating ips based on target range
def generate_ips(start_ip, end_ip, skip=1):
    start = ipaddress.IPv4Address(start_ip)
    end = ipaddress.IPv4Address(end_ip)
    ips = []

    current = start
    while current <= end:
        ips.append(str(current))
        current += skip

    return ips


# main program, runs traceroute and stores result to JSON
if __name__ == '__main__':
    results = {}
    # private ip address range
    public_ip_range = generate_ips("10.0.0.0", "10.255.255.255", skip=8)
    # public ip address range
    # public_ip_range = generate_ips("138.238.0.0", "138.238.255.255", skip=1)
    trace_route_with_threads(public_ip_range, results)

    # save the results to a JSON file
    with open("traceroute_results.json", "a") as json_file:
        json.dump(results, json_file, indent=4)

