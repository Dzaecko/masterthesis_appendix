import os
import json
from collections import defaultdict

# Path to the folder containing JSON files, using a raw string
directory_path = r'C:\Users\Dzaecko\Downloads\cvelistV5-main\cvelistV5-main\cvelist'

# Dictionary to store the count of different CVSS versions
cvss_counts = defaultdict(int)
total_files_with_cvss = 0
total_files = 0

# Traverse all files in the specified directory
for filename in os.listdir(directory_path):
    file_path = os.path.join(directory_path, filename)
    if file_path.endswith('.json'):
        with open(file_path, 'r', encoding='utf-8') as file:
            total_files += 1
            data = json.load(file)
            found_cvss = False  # Marker for whether a CVSS entry was found
            # Check if the "metrics" field exists in the "containers"
            containers = data.get('containers', {})
            if 'cna' in containers:
                metrics = containers['cna'].get('metrics', [])
                for metric in metrics:
                    # Search all keys in each metric object
                    for key in metric.keys():
                        if key.startswith('cvss'):
                            version = metric[key].get('version', 'unknown')
                            cvss_counts[version] += 1
                            found_cvss = True  # Set the marker as a CVSS entry was found
            if found_cvss:
                total_files_with_cvss += 1

# Output the collected CVSS versions and their counts
for version, count in cvss_counts.items():
    print(f"CVSS {version}: {count} times")

# Output how many files contain at least one CVSS entry
print(f"Number of files with at least one CVSS entry: {total_files_with_cvss} out of {total_files} files")
