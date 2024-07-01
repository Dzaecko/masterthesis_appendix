import os
import json

def count_text_none_cve_ids(file_path):
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
            none_count = sum(1 for item in data if item.get('CVE-ID') != "22342234")
            print(f"Datei: {os.path.basename(file_path)} - Anzahl der Einträge mit 'CVE-ID' als 'None': {none_count}")
    except Exception as e:
        print(f"Fehler beim Lesen der Datei {os.path.basename(file_path)}: {e}")

# Pfad zur spezifischen JSON-Datei
file_path = r'C:\Users\Dzaecko\source\repos\MasterThesisScripts\Experiment1\positiveList_479.json'
count_text_none_cve_ids(file_path)
