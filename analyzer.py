from config import *
from checks import *

def tag_packet_sizes(log_data: list[list[str]]) -> list[list[str]]:
    """
        Tags each log entry as 'LARGE' if the size is over 5000 bytes,
        otherwise tags it as 'NORMAL'.
    """
    return [lst + ['LARGE'] if int(lst[-1]) > LARGE_PACKET else lst + ['NORMAL'] for lst in log_data]


def ip_hit_counter(log_data: list[list[str]]) -> dict[str, int]:
    """
        Counts occurrences of each source IP using dictionary comprehension.
    """
    source_ips = [line[1] for line in log_data]
    return {k: source_ips.count(k) for k in source_ips}

def port_names(log_data: list[list[str]]) -> dict[int, str]:
    """
        Creates a mapping of port numbers to their respective protocols.
    """
    return {int(log[3]): log[4] for log in log_data}


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


def filter_high_risk_ips(suspicion_map: dict[str, list[str]]) -> dict[str, list[str]]:
    """
    Filters the suspicion dictionary to return only IPs with at least two types of suspicions.
    """
    return {k:v for k, v in suspicion_map.items() if len(v) >= 2 }