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


def external_ip(line):
    return "EXTERNAL_IP" if line[1][:3] not in EXTERNAL_IP and line[1][:7] not in EXTERNAL_IP else None

def sensitive_port(line):
    return "SENSITIVE_PORT" if line[4] in SENSITIVE_PORT else None


def large_packets(line):
    return "LARGE_PACKET" if int(line[-1]) > LARGE_PACKET else None

def night_activity(line):
    return 'NIGHT_ACTIVITY' if (NIGHT_ACTIVITY[0] < NIGHT_ACTIVITY[1] and line[0][11:16] > NIGHT_ACTIVITY[0] and line[0][11:16] < NIGHT_ACTIVITY[1]) or(NIGHT_ACTIVITY[0] > NIGHT_ACTIVITY[1] and line[0][11:16] > NIGHT_ACTIVITY[1] or line[0][11:16] < NIGHT_ACTIVITY[0]) else None


def map_ip_suspicions(log_data: list[list[str]]) -> dict[str, list[str]]:
    """
    Identifies suspicious activities for each source IP and maps them to a list of suspicion types.
    """
    return {line[1]: [suspicion for suspicion in [external_ip(line) , sensitive_port(line), large_packets(line), night_activity(line),]if suspicion is not None] for line in log_data}



