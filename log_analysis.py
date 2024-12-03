# """
# Log Analysis Script
# Author: Mridul Krishna Gupta
# Date: 03-Dec-2024
# Description: Analyzes server log files for request counts, most accessed endpoints, and suspicious activities.
# """


import csv
from collections import defaultdict

def read_log_file(file_path):
    with open(file_path, 'r') as file:
        return file.readlines()

def count_requests_per_ip(log_lines):
    ip_counts = defaultdict(int)
    for line in log_lines:
        ip = line.split(' ')[0]
        ip_counts[ip] += 1
    return sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)

def find_most_accessed_endpoint(log_lines):
    endpoint_counts = defaultdict(int)
    for line in log_lines:
        endpoint = line.split('"')[1].split(' ')[1]
        endpoint_counts[endpoint] += 1
    return max(endpoint_counts.items(), key=lambda x: x[1])

def detect_suspicious_activity(log_lines, threshold=10):
    failed_attempts = defaultdict(int)
    for line in log_lines:
        if '401' in line:
            ip = line.split(' ')[0]
            failed_attempts[ip] += 1
    return {ip: count for ip, count in failed_attempts.items() if count > threshold}

def save_results_to_csv(ip_requests, most_accessed, suspicious_activities):
    with open('log_analysis_results.csv', 'w', newline='') as file:
        writer = csv.writer(file)

        writer.writerow(['IP Address', 'Request Count'])
        writer.writerows(ip_requests)

        writer.writerow([])
        writer.writerow(['Most Accessed Endpoint', 'Access Count'])
        writer.writerow(most_accessed)

        writer.writerow([])
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in suspicious_activities.items():
            writer.writerow([ip, count])

def main():
    log_lines = read_log_file('sample.log')

    ip_requests = count_requests_per_ip(log_lines)
    most_accessed = find_most_accessed_endpoint(log_lines)
    suspicious_activities = detect_suspicious_activity(log_lines)

    print("IP Address Request Count:")
    for ip, count in ip_requests:
        print(f"{ip} - {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} - {most_accessed[1]} accesses")

    print("\nSuspicious Activities Detected:")
    for ip, count in suspicious_activities.items():
        print(f"{ip} - {count} failed login attempts")

    save_results_to_csv(ip_requests, most_accessed, suspicious_activities)

if __name__ == "__main__":
    main()


# How the Code Works

# 1. Importing Libraries
# csv: To save results into a CSV file.
# defaultdict: A dictionary that returns a default value if the key does not exist.
# 
# 2. Functions
# read_log_file: Reads the log file (sample.log) and returns all lines as a list.
# count_requests_per_ip: Counts how many requests were made by each IP address.
# find_most_accessed_endpoint: Identifies the endpoint (URL) that was accessed the most times.
# detect_suspicious_activity: Detects IPs with more than 10 failed login attempts (status code 401).
# save_results_to_csv: Saves the analysis results into a CSV file named log_analysis_results.csv.
# main: The main driver function that calls the above functions and prints the results in the terminal.

# 3. Execution Workflow
# The script reads the sample.log file.
# It analyzes the log file for:
# Request counts by IP.
# The most frequently accessed endpoint.
# IPs with suspicious login attempts.
# The results are printed in the terminal and saved to a CSV file.