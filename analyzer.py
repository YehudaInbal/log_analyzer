def size_tagging(data):
    return [lst + ['LARGE'] if int(lst[-1]) > LARGE_PACKET else lst + ['NORMAL'] for lst in data]