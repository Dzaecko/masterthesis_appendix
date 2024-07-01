import os
import json
import requests
import csv
import time

# Setzen Sie den Pfad zum Verzeichnis der JSON-Dateien
input_directory = r'C:\Users\Dzaecko\Downloads\cvelistV5-main\cvelistV5-main\cvelist'
# Setzen Sie den Pfad zum Verzeichnis der CSV-Dateien
output_directory = r'C:\Users\Dzaecko\Downloads\cvelistV5-main\cvelistV5-main\basescore'

# CSV-Datei vorbereiten
csv_file_number = 1
max_size = 60000
csv_filename = os.path.join(output_directory, f'output_{csv_file_number}.csv')

def create_csv(filename):
    with open(filename, 'w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(['CVE-ID', 'Basis Score', 'Vector String'])

def append_to_csv(filename, data):
    with open(filename, 'a', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(data)

# Erstellen Sie die erste CSV-Datei
create_csv(csv_filename)

# Funktion zum Abrufen von CVE-Details von der NVD API
def get_cve_details(cve_id):
    url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}'
    try:
        response = requests.get(url)
        response.raise_for_status()  # Löst eine Exception aus, wenn der Status-Code ein Fehler ist
        data = response.json()
        if data['totalResults'] > 0:
            vuln = data['vulnerabilities'][0]
            # Überprüfen, ob die benötigten Daten verfügbar sind und ggf. Alternativen nutzen
            if 'cvssMetricV31' in vuln['cve']['metrics']:
                metric = vuln['cve']['metrics']['cvssMetricV31'][0]['cvssData']
            elif 'cvssMetricV2' in vuln['cve']['metrics']:
                metric = vuln['cve']['metrics']['cvssMetricV2'][0]['cvssData']
            else:
                return [cve_id, 'N/A', 'N/A']  # Keine Metriken verfügbar
            
            base_score = metric.get('baseScore', 'N/A')
            vector_string = metric.get('vectorString', 'N/A')
            return [cve_id, base_score, vector_string]
    except requests.RequestException:
        time.sleep(60)  # Warten Sie eine Minute
        return get_cve_details(cve_id)  # Versuchen Sie es erneut
    return [cve_id, 'N/A', 'N/A']

# Durchlaufen aller Dateien im Verzeichnis
for filename in os.listdir(input_directory):
    if filename.endswith(".json"):
        with open(os.path.join(input_directory, filename), 'r', encoding='utf-8') as json_file:
            data = json.load(json_file)
            cve_id = data['cveMetadata']['cveId']
            cve_data = get_cve_details(cve_id)
            append_to_csv(csv_filename, cve_data)
            
            # Überprüfen Sie die Größe der Datei und erstellen Sie ggf. eine neue
            if os.path.getsize(csv_filename) >= max_size:
                csv_file_number += 1
                csv_filename = os.path.join(output_directory, f'output_{csv_file_number}.csv')
                create_csv(csv_filename)
