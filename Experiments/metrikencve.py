import pandas as pd
import numpy as np
import os
import json
import re

# Paths and data loading
json_file_path = 'positiveList_479.json'
input_csv_path = 'results_llama_index_gpt4_turbo.csv'
df_results = pd.read_csv(input_csv_path, delimiter=';')
df_positives = pd.read_json(json_file_path)

# Prepare data
df_positives['Version'] = df_positives['Version'].astype(str)

# Initialize metrics
TP = FP = TN = FN = 0
extra_tp_detected = 0  # Counter for detected TPs that were not initially recognized

# Function to extract and compare CVE IDs
def extract_cve_ids(cve_string):
    if pd.notna(cve_string):
        return set(cve_id.strip() for cve_id in cve_string.split(',') if cve_id.strip())
    else:
        return set()

# Function to extract version numbers from version strings
def extract_version_numbers(version_string):
    return re.findall(r'\d+(?:\.\d+)*', version_string)

# Function to recursively search for matches in JSON data
def is_match_in_json_data(data, software, versions):
    if isinstance(data, dict):
        for value in data.values():
            if is_match_in_json_data(value, software, versions):
                return True
    elif isinstance(data, list):
        for item in data:
            if is_match_in_json_data(item, software, versions):
                return True
    elif isinstance(data, str):
        lower_data = data.lower()
        software_in_data = software.lower() in lower_data
        version_in_data = any(version.lower() in lower_data for version in versions)
        return software_in_data and version_in_data
    return False

# Function to check for CVE files, considering the possibility of subdirectories
cve_directory_path = r'C:\Users\Dzaecko\Downloads\cvelistV5-main\cvelistV5-main\cvelist'
def check_cve_files(cve_id, software, version_string):
    versions = extract_version_numbers(version_string)
    for root, dirs, files in os.walk(cve_directory_path):
        if f"{cve_id}.json" in files:
            cve_file_path = os.path.join(root, f"{cve_id}.json")
            if os.path.exists(cve_file_path):
                with open(cve_file_path, 'r', encoding='utf-8') as file:
                    try:
                        data = json.load(file)
                        if is_match_in_json_data(data, software, versions):
                            return True
                    except json.JSONDecodeError:
                        print(f"Error decoding JSON from {cve_file_path}")
    return False

# Conduct the comparison
for index, row in df_results.iterrows():
    software = row['Software']
    version = row['Version']
    if str(version).lower() == 'n/a':
        version = 'n/a'

    result_cve_ids = extract_cve_ids(row['LLMsaysThisCVEId'])

# Adjust the comparison to handle 'n/a' correctly
    matching_positives = df_positives[(df_positives['Software'] == software) &
                                  (df_positives['Version'].astype(str).str.contains(version, na=False, regex=False))]
   

    positive_cve_ids = set()
    for _, positive_row in matching_positives.iterrows():
        positive_cve_ids.update(extract_cve_ids(positive_row['CVE-ID']))

    if result_cve_ids:
        if positive_cve_ids:
            if result_cve_ids & positive_cve_ids:
                TP += 1
            else:
                potential_fp = False
                for cve_id in result_cve_ids:
                    if check_cve_files(cve_id, software, version):
                        TP += 1
                        extra_tp_detected += 1
                        break
                    else:
                        potential_fp = True
                if potential_fp:
                    FP += 1
        else:
            FP += 1
    else:
        if positive_cve_ids:
            FN += 1
        else:
            TN += 1

# Calculate metrics
total = TP + TN + FP + FN
accuracy = (TP + TN) / total if total > 0 else 0
precision = TP / (TP + FP) if (TP + FP) > 0 else 0
recall = TP / (TP + FN) if (TP + FN) > 0 else 0
f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
mcc_numerator = (TP * TN) - (FP * FN)
mcc_denominator = np.sqrt((TP + FP) * (TP + FN) * (TN + FP) * (TN + FN))
mcc = mcc_numerator / mcc_denominator if mcc_denominator > 0 else 0

# Output results
print(f"Confusion Matrix: TP={TP}, FP={FP}, TN={TN}, FN={FN}")
print(f"Extra TP Detected: {extra_tp_detected}")
print(f"Accuracy: {accuracy:.4f}, Precision: {precision:.4f}, Recall: {recall:.4f}, F1-Score: {f1_score:.4f}, MCC: {mcc:.4f}")
