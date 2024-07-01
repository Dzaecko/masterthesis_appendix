import csv
import json

# Pfad zu Ihrer CSV- und JSON-Datei
csv_file_path = 'results_llama_index_gpt4_turbo.csv'
json_file_path = 'positiveList_479.json'

# Funktion zur Überprüfung, ob eine gültige CVE-ID vorhanden ist
def has_valid_cve_id(entry):
    cve_id = entry.get("LLMsaysThisCVEId", "").strip()
    return "CVE-" in cve_id.upper()

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

# Zählvariablen für TP, FN, FP, TN initialisieren
tp = 0
fn = 0
fp = 0
tn = 0

# Überprüfen jeder Software in der Ergebnisliste (CSV) gegen die PositiveList (JSON)
for csv_entry in csv_data:
    software = csv_entry["Software"]
    version = csv_entry["Version"]
    has_vuln_csv = csv_entry["LLMSaysHasVulnerability"] == 1
    csv_cve_id = csv_entry.get("LLMsaysThisCVEId", "").strip().lower()
    
    # Suche nach entsprechenden Einträgen in der Positivliste
    json_entry = next((item for item in json_data if item["Software"] == software and item["Version"] == version), None)

    if json_entry:
        json_cve_id = json_entry.get("CVE-ID", "").strip().lower()
        
        # Entscheidungslogik für TP, FN, FP, TN
        if has_vuln_csv:
            if "cve-" in json_cve_id and json_cve_id in csv_cve_id:
                tp += 1
            else:
                fp += 1
        else:
            if "cve-" in json_cve_id and json_cve_id not in csv_cve_id:
                fn += 1
            else:
                tn += 1

    else:
        # Fall: Software/Version nicht in der Positivliste gefunden
        if has_vuln_csv:
            fp += 1  # Annahme: Wenn nicht in Positivliste, dann als FP behandeln
        else:
            tn += 1  # Keine Schwachstelle gemeldet und nicht in Positivliste

# Berechnung der Metriken
def calculate_metrics(tp, tn, fp, fn):
    def safe_div(n, d):
        return n / d if d else 0

    accuracy = safe_div((tp + tn), (tp + tn + fp + fn))
    recall = safe_div(tp, (tp + fn))
    precision = safe_div(tp, (tp + fp))
    f1 = safe_div(2 * (precision * recall), (precision + recall))
    mcc_numerator = (tp * tn) - (fp * fn)
    mcc_denominator = ((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)) ** 0.5
    mcc = safe_div(mcc_numerator, mcc_denominator)

    return accuracy, recall, precision, f1, mcc

accuracy, recall, precision, f1, mcc = calculate_metrics(tp, tn, fp, fn)

# Ausgabe der Ergebnisse
print(f"True Positives (TP): {tp}")
print(f"False Negatives (FN): {fn}")
print(f"False Positives (FP): {fp}")
print(f"True Negatives (TN): {tn}")
print(f"Accuracy: {accuracy:.4f}")
print(f"Recall: {recall:.4f}")
print(f"Precision: {precision:.4f}")
print(f"F1-Score: {f1:.4f}")
print(f"MCC: {mcc:.4f}")