import os
import json
import random

def extract_cvss_data(filepath):
    with open(filepath, 'r', encoding='utf-8') as file:
        data = json.load(file)
        for container in data.get('containers', {}).values():
            if 'metrics' in container:
                for metric in container['metrics']:
                    if 'cvssV3_1' in metric:
                        cvss_data = metric['cvssV3_1']
                        if 'attackVector' in cvss_data:
                            return {
                                "user": "Describe me the CVSS metrics for that vulnerability: "+container['descriptions'][0]['value'],
                                "assistant": format_assistant_response(cvss_data)
                            }
    return None

def format_assistant_response(cvss_data):
    response = (
        f"This vulnerability can be exploited from {cvss_data.get('attackVector', 'N/A').replace('_', ' ').lower()} as Attack Vector and requires "
        f"{cvss_data.get('attackComplexity', 'N/A').lower()} attack complexity. It demands {cvss_data.get('privilegesRequired', 'N/A').lower()} "
        f"user privileges and {cvss_data.get('userInteraction', 'N/A').lower().replace('_', ' ')} user interaction. The impact of this vulnerability "
        f"is {cvss_data.get('scope', 'N/A').lower()} scope with a {cvss_data.get('confidentialityImpact', 'N/A').lower()} impact on confidentiality, "
        f"{cvss_data.get('integrityImpact', 'N/A').lower()} impact on integrity, and {cvss_data.get('availabilityImpact', 'N/A').lower()} impact on availability. "
        f"The CVSS specified by the vector string '{cvss_data.get('vectorString', 'N/A')}'."
    )
    return response

def scan_directory(directory, output_file_main, output_file_validation, max_files_main=1000, max_files_validation=100):
    json_files = [os.path.join(root, file) for root, dirs, files in os.walk(directory) for file in files if file.endswith('.json')]
    random.shuffle(json_files)  # Randomize the order of files
    
    count_main = 0
    count_validation = 0
    validation_entries = []
    with open(output_file_main, 'w') as main_file:
        for filepath in json_files:
            if count_main >= max_files_main and count_validation >= max_files_validation:
                break
            cvss_data = extract_cvss_data(filepath)
            if cvss_data:
                entry = {
                    "messages": [
                        {"role": "system", "content": "Let's discuss details about specific types of vulnerabilities and their CVSS metrics."},
                        {"role": "user", "content": cvss_data['user']},
                        {"role": "assistant", "content": cvss_data['assistant']}
                    ]
                }
                if count_main < max_files_main:
                    count_main += 1
                    main_file.write(json.dumps(entry) + '\n')
                elif count_validation < max_files_validation:
                    count_validation += 1
                    validation_entries.append(entry)

    # Write to validation file after main file processing
    with open(output_file_validation, 'w') as validation_file:
        for entry in validation_entries:
            validation_file.write(json.dumps(entry) + '\n')

# Define the directory to scan and the output file paths
directory_path = r'C:\Users\Dzaecko\Downloads\cvelistV5-main\cvelistV5-main\cvelist'
output_path_main = r'C:\Users\Dzaecko\Downloads\output_main_n1.jsonl'
output_path_validation = r'C:\Users\Dzaecko\Downloads\output_validation_n1.jsonl'

# Call the function to scan the directory and write to the output files
scan_directory(directory_path, output_path_main, output_path_validation)
