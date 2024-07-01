import os
import json

def extract_important_info_and_split(root_dir, output_directory, number_of_splits=15):
    extracted_data = []  # Liste zum Speichern der extrahierten Daten
    file_count = 0  # Zähler für die verarbeiteten Dateien

    for root, dirs, files in os.walk(root_dir):
        for file in files:
            if file.endswith('.json'):
                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if isinstance(data, dict):  # Wenn data ein Dictionary ist
                        cve_id = data.get("cveMetadata", {}).get("cveId", "N/A")
                        descriptions = data.get("containers", {}).get("cna", {}).get("descriptions", [])
                        description = " ".join([desc.get("value", "") for desc in descriptions]) if descriptions else "empty"
                        affected_versions = [ver.get("version", "n/a") for aff in data.get("containers", {}).get("cna", {}).get("affected", []) for ver in aff.get("versions", [])]
                        affected_versions = affected_versions if affected_versions else ["empty"]
                        extracted_data.append({
                            "cveId": cve_id,
                            "version": affected_versions,
                            "description": description
                        })
                file_count += 1

    # Bestimmen, wie viele Einträge pro Datei benötigt werden
    total_entries = len(extracted_data)
    entries_per_file = max(total_entries // number_of_splits, 1)  # Vermeiden von Division durch 0

    # Aufteilen und Speichern der Daten in mehrere Dateien
    for i in range(number_of_splits):
        start_index = i * entries_per_file
        end_index = start_index + entries_per_file
        # Für die letzte Datei alle verbleibenden Einträge hinzufügen
        if i == number_of_splits - 1:
            end_index = total_entries
        subset = extracted_data[start_index:end_index]

        output_file_path = os.path.join(output_directory, f'extracted_data_part_{i+1}.json')
        with open(output_file_path, 'w', encoding='utf-8') as outfile:
            json.dump(subset, outfile, ensure_ascii=False, indent=4)

# Pfad zu Ihrem Hauptverzeichnis
root_directory = r'C:\Users\Dzaecko\Downloads\cvelistV5-main\cvelistV5-main\cves'
output_directory = r'C:\Users\Dzaecko\Downloads\cvelistV5-main\cvelistV5-main\mix'  # Stellen Sie sicher, dass dieser Ordner existiert

# Funktion aufrufen
extract_important_info_and_split(root_directory, output_directory)
