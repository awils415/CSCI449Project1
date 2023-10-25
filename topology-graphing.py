import networkx as nx
import matplotlib.pyplot as plt
import json

def load_traceroute_results(filename):
    with open(filename, 'r') as json_file:
        return json.load(json_file)

def build_network_graph(results):
    G = nx.Graph()
    for destination_ip, hops in results.items():
        prev_ip = None
        for hop in hops:
            current_ip = hop['ip']
            if not G.has_node(current_ip):
                G.add_node(current_ip)
            if prev_ip and prev_ip != current_ip and not G.has_edge(prev_ip, current_ip):
                G.add_edge(prev_ip, current_ip)
            prev_ip = current_ip
    return G

if __name__ == '__main__':
    json_filename = "traceroute_results.json"
    traceroute_results = load_traceroute_results(json_filename)

    network_graph = build_network_graph(traceroute_results)

    pos = nx.spring_layout(network_graph)
    nx.draw(network_graph, pos, with_labels=True, node_size=500, node_color='skyblue', font_size=8)
    plt.title("Network Topology")
    plt.show()
