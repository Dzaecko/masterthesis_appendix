import os
import json

def check_json_files(directory):
    total_files = 0
    missing_name_and_version = 0
    missing_version = 0

    for filename in os.listdir(directory):
        if filename.endswith('.json'):
            total_files += 1
            path = os.path.join(directory, filename)

            with open(path, 'r', encoding='utf-8') as file:  
                try:
                    data = json.load(file)
                except json.JSONDecodeError as e:
                    print(f"Error decoding JSON from {filename}: {e}")
                    continue  
                
                containers = data.get('containers', {})
                for container in containers.values():
                    affected = container.get('affected', [])
                    for product_info in affected:
                        product_name = product_info.get('product', 'n/a')
                        vendor_name = product_info.get('vendor', 'n/a')
                        versions = product_info.get('versions', [])
                        
                        version_set = any(version.get('version', 'n/a') != 'n/a' for version in versions)
                        
                       
                        if (product_name == 'n/a' and vendor_name == 'n/a') or not version_set:
                            missing_name_and_version += 1
                        if not version_set:
                            missing_version += 1

    if total_files > 0:
        percent_missing_both = (missing_name_and_version / total_files) * 100
        percent_missing_version = (missing_version / total_files) * 100
    else:
        percent_missing_both = 0
        percent_missing_version = 0

    return {
        "total_files": total_files,
        "files_with_no_name_or_version": missing_name_and_version,
        "files_with_no_version": missing_version,
        "percent_missing_name_or_version": percent_missing_both,
        "percent_missing_version": percent_missing_version
    }

path_to_directory = r'C:\Users\Dzaecko\Downloads\cvelistV5-main\cvelistV5-main\cvelist'
results = check_json_files(path_to_directory)
print(results)
