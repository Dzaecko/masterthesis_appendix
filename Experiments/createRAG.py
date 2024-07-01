import json
import os
import csv

def extract_data(json_file):
    with open(json_file, 'r', encoding='utf-8') as file:
        data = json.load(file)
    
    # Check if the state is PUBLISHED
    if data.get('cveMetadata', {}).get('state') != 'PUBLISHED':
        return None

    cve_id = data.get('cveMetadata', {}).get('cveId', 'None')
    descriptions = data.get('containers', {}).get('cna', {}).get('problemTypes', [{}])[0].get('descriptions', [{}])[0].get('description', 'None')
    vector_string = data.get('containers', {}).get('cna', {}).get('metrics', [{}])[0].get('cvssV3_1', {}).get('vectorString', 'None')
    general_description = data.get('containers', {}).get('cna', {}).get('descriptions', [{}])[0].get('value', 'None')
    return [cve_id, general_description, vector_string, descriptions]

def write_to_csv(output_dir, data, file_index):
    csv_path = os.path.join(output_dir, f'output_{file_index}.csv')
    with open(csv_path, 'w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(['CVE-ID', 'Description', 'vectorString', 'CWE-Description'])
        for row in data:
            writer.writerow(row)

def process_files(input_dir, output_dir, limit=None):
    files = [f for f in os.listdir(input_dir) if f.endswith('.json')]
    all_data = []
    current_size = 0
    file_index = 1
    entries_count = 0  # Variable to count the number of entries processed

    if limit:
        files = files[:limit]

    for filename in files:
        full_path = os.path.join(input_dir, filename)
        extracted_data = extract_data(full_path)
        if extracted_data:
            serialized = ','.join(extracted_data)
            if current_size + len(serialized) > 60000:
                write_to_csv(output_dir, all_data, file_index)
                all_data = [extracted_data]
                file_index += 1
                current_size = len(serialized)
            else:
                all_data.append(extracted_data)
                current_size += len(serialized)
            entries_count += 1  # Update count on successful extraction

    if all_data:
        write_to_csv(output_dir, all_data, file_index)

    return entries_count

input_dir = r'C:\Users\Dzaecko\Downloads\cvelistV5-main\cvelistV5-main\cvelist'
output_dir = r'C:\Users\Dzaecko\Downloads\cvelistV5-main\cvelistV5-main\rag1'
total_entries = process_files(input_dir, output_dir, limit=None)  # Set limit=None to process all files or specify a number to limit

print(f'Total entries processed: {total_entries}')
