import os
import json
import random

# Pfad zum Ordner mit JSON-Dateien
folder_path = r"C:\Users\Dzaecko\Downloads\cvelistV5-main\cvelistV5-main\cvelist"
output_files = {}

# Dictionary zum Sammeln von Datensätzen für jede CVSS-Metrik
records_by_metric = {}

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
                # Spalte den Vektor-String und erstelle einen Eintrag für jede Metrik
                metrics_list = vector_string.split('/')
                for m in metrics_list[1:]:  # Skip the first entry "CVSS:3.1"
                    metric_key, metric_value = m.split(':')
                    metric_full = f"{metric_key}:{metric_value}"
                    if metric_key not in records_by_metric:
                        records_by_metric[metric_key] = []
                    records_by_metric[metric_key].append({
                        "messages": [
                            {"role": "system", "content": "The model should determine the CVSS vector for the given CVE description."},
                            {"role": "user", "content": description},
                            {"role": "assistant", "content": metric_full}
                        ]
                    })

# Erstelle zwei Dateien für jede Metrik: eine mit 200 und eine mit 40 Einträgen
for metric_key, records in records_by_metric.items():
    random.shuffle(records)

    # Datei mit 200 Einträgen
    output_file_200 = f"{metric_key}_200_output.jsonl"
    with open(output_file_200, "w", encoding="utf-8") as file:
        for record in records[:200]:  # Begrenze auf 200 Einträge
            file.write(json.dumps(record) + "\n")
    output_files[f"{metric_key}_200"] = output_file_200

    # Datei mit 40 Einträgen
    output_file_40 = f"{metric_key}_40_output.jsonl"
    with open(output_file_40, "w", encoding="utf-8") as file:
        for record in records[:40]:  # Begrenze auf 40 Einträge
            file.write(json.dumps(record) + "\n")
    output_files[f"{metric_key}_40"] = output_file_40

print("Zufällige Ausgaben für jede Metrik wurden erstellt.")
print("Dateien:", output_files)
