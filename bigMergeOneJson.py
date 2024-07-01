import os
import json
import glob
import random

# Pfade definieren
root_directory = r'C:\Users\Dzaecko\Downloads\cvelistV5-main\cvelistV5-main\cves'
# Zielordner für die neuen Dateien, aktualisierter Pfad entsprechend Ihrer Anforderung
output_directory = r'C:\Users\Dzaecko\source\repos\MasterThesisScripts\docs'

# Stellen Sie sicher, dass der Zielordner existiert
if not os.path.exists(output_directory):
    os.makedirs(output_directory)

# Liste aller Dateipfade generieren
all_file_paths = glob.glob(os.path.join(root_directory, '**', '*.json'), recursive=True)

# 4000 zufällige Dateien auswählen, wenn weniger vorhanden sind, alle auswählen
selected_file_paths = random.sample(all_file_paths, min(4000, len(all_file_paths)))

# Zähler für die Verarbeitung der Dateien
processed_files = 0

for file_path in selected_file_paths:
    with open(file_path, 'r', encoding='utf-8') as file:
        data = json.load(file)
        
        # Bestimmte Schlüssel aus 'cveMetadata' entfernen
        keys_to_remove = ['assignerOrgId', 'assignerShortName', 'dateReserved', 'dateUpdated', 'state']
        data['cveMetadata'] = {key: value for key, value in data['cveMetadata'].items() if key not in keys_to_remove}
        
        # 'dataType' und 'dataVersion' entfernen
        if 'dataType' in data:
            del data['dataType']
        if 'dataVersion' in data:
            del data['dataVersion']

        # 'providerMetadata' aus 'containers' entfernen
        for container_key in data['containers']:
            if 'providerMetadata' in data['containers'][container_key]:
                del data['containers'][container_key]['providerMetadata']

        # Eindeutigen Namen für die neue Datei generieren, basierend auf der cveId
        output_file_name = data['cveMetadata']['cveId'] + '.json'
        output_file_path = os.path.join(output_directory, output_file_name)
        
        # Speichere die modifizierte Datei im Zielordner ohne Einrückung, um Speicherplatz zu sparen
        with open(output_file_path, 'w', encoding='utf-8') as output_file:
            json.dump(data, output_file, ensure_ascii=False, separators=(',', ':'))
                
        processed_files += 1

print(f"Verarbeitung abgeschlossen. {processed_files} Dateien wurden verarbeitet und im Ordner '{output_directory}' gespeichert.")
