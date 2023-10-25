import sys
import os
import ipaddress
from scapy.all import *
import threading
import json

results_lock = threading.Lock()
file_lock = threading.Lock()
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
            with results_lock:
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
    # public_ip_range = generate_ips("10.0.0.0", "10.255.255.255", skip=8)
    # public ip address range
    if len(sys.argv) != 3:
        print("Usage: python your_script.py <start_ip> <end_ip>")
        sys.exit(1)
    start_ip = sys.argv[1]
    end_ip = sys.argv[2]
    public_ip_range = generate_ips(start_ip, end_ip, skip=64)
    trace_route_with_threads(public_ip_range, results)
    print("DONE?")
    try:
        with file_lock:
            with open("traceroute_results.json", "a+") as json_file:
                json.dump(results, json_file, indent=4)
    except Exception as e:
        print("An error occurred while writing to the JSON file:", str(e))
