import csv
import json

# Pfad zu Ihrer CSV- und JSON-Datei
csv_file_path = 'ergebnissellama70B_neu.csv'
json_file_path = 'positiveList_145 copy.json'

# Einlesen der CSV-Daten
csv_data = []
with open(csv_file_path, mode='r', encoding='utf-8') as csv_file:
    csv_reader = csv.DictReader(csv_file, delimiter=';')
    for row in csv_reader:
        row['LLMSaysHasVulnerability'] = int(row.get('LLMSaysHasVulnerability', 0))
        csv_data.append(row)

# Einlesen der JSON-Daten
with open(json_file_path, mode='r', encoding='utf-8') as json_file:
    json_data = json.load(json_file)

# Zählvariablen für TP, FN, FP, TN initialisieren und eine Variable für nicht gefundene Einträge
tp = 0
fn = 0
fp = 0
tn = 0
not_found_in_positive_list = 0

# Überprüfen jeder Software in der Ergebnisliste (CSV) gegen die PositiveList (JSON)
for csv_entry in csv_data:
    software = csv_entry["Software"]
    csv_has_vulnerability = csv_entry["LLMSaysHasVulnerability"] == 1

    # Suche nach einem passenden Eintrag in der JSON-Daten
    json_entry = next((item for item in json_data if item["Software"] == software), None)

    if json_entry:
        json_has_vulnerability = json_entry["VulnerabilityType"].lower() != "none" and json_entry["CVE-ID"].lower() != "n/a"
        if csv_has_vulnerability and json_has_vulnerability:
            tp += 1
        elif not csv_has_vulnerability and json_has_vulnerability:
            fn += 1
        elif csv_has_vulnerability and not json_has_vulnerability:
            fp += 1
        elif not csv_has_vulnerability and not json_has_vulnerability:
            tn += 1
    else:
        # Zählt Fälle, in denen kein Eintrag in der PositiveList gefunden wird
        not_found_in_positive_list += 1

# Ausgabe der Ergebnisse
print(f"True Positives (TP): {tp}")
print(f"False Negatives (FN): {fn}")
print(f"False Positives (FP): {fp}")
print(f"True Negatives (TN): {tn}")
print(f"Nicht in der PositiveList gefunden: {not_found_in_positive_list}")
