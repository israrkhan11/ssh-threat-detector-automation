import re
from collections import defaultdict

FAILED_PATTERN = r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)"

def parse_failed_logins(log_lines):

    ip_counts = defaultdict(int)

    for line in log_lines:

        match = re.search(FAILED_PATTERN, line)

        if match:
            ip = match.group(1)
            ip_counts[ip] += 1

    return ip_counts


def detect_threats(ip_counts, threshold):

    threats = {}

    for ip, count in ip_counts.items():
 
        if count >= threshold:
            threats[ip] = count

    return threats
