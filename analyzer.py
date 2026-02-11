from config import *
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
