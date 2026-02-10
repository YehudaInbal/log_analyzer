from config import *

def suspicious_ips(data):
    return [list for list in data if list[1][:3] not in EXTERNAL_IP and list[1][:7] not in EXTERNAL_IP]

def suspicious_ports(data):
    return [list for list in data if list[4] in SENSITIVE_PORT]