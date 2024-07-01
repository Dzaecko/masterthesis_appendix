import os
import json
import random

input_directory_path = r'C:\Users\Dzaecko\Downloads\cvelistV5-main\cvelistV5-main\cvelist'
output_directory_path = r'C:\Users\Dzaecko\Downloads\cvelistV5-main\cvelistV5-main'

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
                                "Description": container['descriptions'][0]['value'],
                                "Classification": format_assistant_response(cvss_data)
                            }
    return None

def write_to_json(data_list, max_chars=60000):
    json_index = 1
    json_content = []
    current_chars = 0
    for data in data_list:
        entry = json.dumps(data)
        if current_chars + len(entry) + len(json_content) > max_chars:
            with open(os.path.join(output_directory_path, f'output_{json_index}.json'), 'w', encoding='utf-8') as f:
                json.dump(json_content, f, indent=4)
            json_index += 1
            json_content = [data]
            current_chars = len(entry)
        else:
            json_content.append(data)
            current_chars += len(entry)
    if json_content:
        with open(os.path.join(output_directory_path, f'output_{json_index}.json'), 'w', encoding='utf-8') as f:
            json.dump(json_content, f, indent=4)

def main():
    json_files = [os.path.join(input_directory_path, f) for f in os.listdir(input_directory_path) if f.endswith('.json')]
    extracted_data = [extract_cvss_data(f) for f in json_files if extract_cvss_data(f) is not None]
    selected_data = random.sample(extracted_data, min(1000, len(extracted_data)))
    write_to_json(selected_data)

if __name__ == "__main__":
    main()
