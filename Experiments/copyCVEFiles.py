import os
import glob
import shutil
from random import sample, shuffle
import re


source_directory = r'C:\Users\Dzaecko\Downloads\cvelistV5-main\cvelistV5-main\cvelist'
target_directory = r'C:\Users\Dzaecko\Downloads\cvelistV5-main\cvelistV5-main\mix'

if not os.path.exists(target_directory):
    os.makedirs(target_directory)

keywords = ["nginx", "mysql", "apache", "phpmyadmin", "mariadb", "wordpress", "drupal", "samba", "postgresql", "postfix", "openssh", "BIND", "Exim", "Squid", "Dovecot", "vsftpd", "proftpd", "openvpn", "gitea"]

def extract_year_and_check(file_name):
    match = re.search(r'CVE-(\d{4})-', file_name)
    if match:
        year = int(match.group(1))
        return 2010 <= year < 2023
    return False


def filter_files(file_path, check_keywords=False):
    
    if not extract_year_and_check(os.path.basename(file_path)):
        return False

    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read().lower()
            if "**REJECTED**" in content or "**RESERVED**" in content:
                return False
            if check_keywords:
                return any(keyword.lower() in content for keyword in keywords)
    except Exception as e:
        print(f"Error while reading {file_path}: {e}")
        return False
    return True

all_files = glob.glob(os.path.join(source_directory, '*.json'))
files_with_keywords = [f for f in all_files if filter_files(f, check_keywords=True)]
remaining_files = [f for f in all_files if filter_files(f) and f not in files_with_keywords]
target_with_keywords = 3500
target_mixed_files = 1500
selected_files_with_keywords = sample(files_with_keywords, min(len(files_with_keywords), target_with_keywords))
additional_needed = target_mixed_files + (target_with_keywords - len(selected_files_with_keywords))
additional_files = sample(remaining_files, min(len(remaining_files), additional_needed))
final_selection = selected_files_with_keywords + additional_files
shuffle(final_selection)  

for file_path in final_selection:
    shutil.copy(file_path, target_directory)

print(f"{len(final_selection)} File are copied to '{target_directory}'")
