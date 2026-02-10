def parse_network_log(path = "network_traffic.log"):
    with open(path, 'r') as file:
        return [line.strip().split(',') for line in file]