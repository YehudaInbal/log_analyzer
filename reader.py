def load_logs(path: str = "network_traffic.log") -> list[list[str]]:
    """
        Receives a path to a CSV file and returns a list of lists,
        where each sub-list represents a log entry row.
    """
    with open(path, 'r') as file:
        return [line.strip().split(',') for line in file]