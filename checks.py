from config import *


def get_external_ips(log_data: list[list[str]]) -> list[list[str]]:
    """
        Filters the log data and returns a list of source IP addresses
        that are not starting with '192.168' or '10.'.
    """
    return [list for list in log_data if list[1][:3] not in EXTERNAL_IP and list[1][:7] not in EXTERNAL_IP]


def filter_sensitive_ports(log_data: list[list[str]]) -> list[list[str]]:
    """
        Filters the log entries and returns only those with sensitive ports:
        22 (SSH), 23 (Telnet), or 3389 (RDP).
    """
    return [list for list in log_data if list[4] in SENSITIVE_PORT]

def filter_large_packets(log_data: list[list[str]], threshold: int = 5000) -> list[list[str]]:
    """
        Filters the log entries and returns only those where the packet size
        is greater than the specified threshold (default is 5000 bytes).
    """
    return[lst for lst in log_data if int(lst[-1]) > LARGE_PACKET]





