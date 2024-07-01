import os
import json
import random

# Pfad zum Ordner mit JSON-Dateien
folder_path = r"C:\Users\Dzaecko\Downloads\cvelistV5-main\cvelistV5-main\cvelist"
output_file_200 = "output_200.jsonl"
output_file_40 = "output_40.jsonl"

# Sammler für Datensätze
records = []

# Liste aller JSON-Dateien im angegebenen Ordner
json_files = [file for file in os.listdir(folder_path) if file.endswith(".json")]

# Durchlaufe alle JSON-Dateien
for file_name in json_files:
    file_path = os.path.join(folder_path, file_name)
    with open(file_path, "r", encoding="utf-8") as file:
        data = json.load(file)
        
        # Versuche, die englische Beschreibung zu finden
        descriptions = data["containers"]["cna"].get("descriptions", [])
        description = next((desc['value'] for desc in descriptions if desc['lang'] == "en"), None)
        
        # Überspringe diesen Eintrag, wenn keine englische Beschreibung vorhanden ist
        if not description:
            continue

        # Überprüfe, ob "metrics" existiert
        metrics = data["containers"]["cna"].get("metrics")
        if not metrics:
            continue

        # Extrahiere den Vektor-String (nur CVSS 3.1)
        for metric in metrics:
            if "cvssV3_1" in metric:
                vector_string = metric["cvssV3_1"]["vectorString"]
                records.append({
                    "messages": [
                        {"role": "system", "content": "The model should determine the CVSS vector for the given CVE description."},
                        {"role": "user", "content": description},
                        {"role": "assistant", "content": vector_string}
                    ]
                })
                break

# Mischen der Datensätze für eine zufällige Auswahl
random.shuffle(records)

# Auswählen von 200 zufälligen Datensätzen
selected_200 = records[:1000]
# Auswählen von 40 zufälligen Datensätzen
selected_40 = records[:200]

# Schreiben der Ergebnisse in die Ausgabedateien
with open(output_file_200, "w", encoding="utf-8") as out_file:
    for record in selected_200:
        out_file.write(json.dumps(record) + "\n")

with open(output_file_40, "w", encoding="utf-8") as out_file:
    for record in selected_40:
        out_file.write(json.dumps(record) + "\n")

print(f"Zufällige Ausgabe fertig: {output_file_200}, {output_file_40}")
