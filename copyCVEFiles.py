import os
import glob
import shutil
from random import sample, shuffle
import re

# Pfade definieren
source_directory = r'C:\Users\Dzaecko\Downloads\cvelistV5-main\cvelistV5-main\cvelist'
target_directory = r'C:\Users\Dzaecko\Downloads\cvelistV5-main\cvelistV5-main\mix'

# Stellen Sie sicher, dass der Zielordner existiert
if not os.path.exists(target_directory):
    os.makedirs(target_directory)

# Liste der Schlüsselwörter
keywords = ["nginx", "mysql", "apache", "phpmyadmin", "mariadb", "wordpress", "drupal", "samba", "postgresql", "postfix", "openssh", "BIND", "Exim", "Squid", "Dovecot", "vsftpd", "proftpd", "openvpn", "gitea"]

# Funktion zum Extrahieren des Jahres aus dem Dateinamen und zur Überprüfung gegen das Jahr 2010 und kleiner als 2023
def extract_year_and_check(file_name):
    match = re.search(r'CVE-(\d{4})-', file_name)
    if match:
        year = int(match.group(1))
        return 2010 <= year < 2023
    return False

# Funktion zum Filtern der Dateien basierend auf dem Dateinamen und dem Inhalt
def filter_files(file_path, check_keywords=False):
    # Überprüfung basierend auf dem Jahr im Dateinamen
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
        print(f"Fehler beim Lesen der Datei {file_path}: {e}")
        return False
    return True

all_files = glob.glob(os.path.join(source_directory, '*.json'))
# Dateien mit Schlüsselwörtern filtern
files_with_keywords = [f for f in all_files if filter_files(f, check_keywords=True)]
# Restliche Dateien filtern
remaining_files = [f for f in all_files if filter_files(f) and f not in files_with_keywords]

# Ziele festlegen
target_with_keywords = 3500
target_mixed_files = 1500

# Auswahl von Dateien mit Schlüsselwörtern, beschränkt auf die Zielanzahl
selected_files_with_keywords = sample(files_with_keywords, min(len(files_with_keywords), target_with_keywords))

# Berechnen, wie viele weitere Dateien benötigt werden, um das Ziel zu erreichen
additional_needed = target_mixed_files + (target_with_keywords - len(selected_files_with_keywords))

# Auswahl aus den verbleibenden Dateien, um die Gesamtzahl zu erreichen
additional_files = sample(remaining_files, min(len(remaining_files), additional_needed))

# Kombinieren der ausgewählten Dateien
final_selection = selected_files_with_keywords + additional_files
shuffle(final_selection)  # Mischen der Liste für Vielfalt

# Jede ausgewählte Datei kopieren
for file_path in final_selection:
    shutil.copy(file_path, target_directory)

print(f"{len(final_selection)} Dateien wurden erfolgreich nach '{target_directory}' kopiert.")
