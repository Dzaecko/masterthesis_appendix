import pandas as pd
import numpy as np

# Pfad zu Ihrer CSV- und JSON-Datei
#csv_file_path_temp = 'results_aisearchgpt4.csv'
json_file_path = 'positiveList_479.json'
# Pfad zur originalen CSV-Datei
input_csv_path = 'results_mistral_clean.csv'

# Einlesen der Daten
df_results = pd.read_csv(input_csv_path, delimiter=';')
df_positives = pd.read_json(json_file_path)

# Vorbereitung der Daten
df_positives['Version'] = df_positives['Version'].astype(str)

# Initialisierung der Metriken
TP = FP = TN = FN = 0

# Durchführung des Vergleichs, indem die Ergebnisliste durchiteriert wird
for index, row in df_results.iterrows():
    software = row['Software']
    version = row['Version']
    llm_says_has_vulnerability = row['LLMSaysHasVulnerability']
    if pd.isna(version):
        version = "n/a"

    # Suche nach passenden Einträgen in der Positivliste
    matching_positives = df_positives[(df_positives['Software'] == software) & 
                                      (df_positives['Version'].astype(str).str.contains(version, regex=False))]

    if not matching_positives.empty:
        # Prüfe, ob im Feld 'CVE-ID' ein gültiger CVE-Code vorhanden ist
        has_valid_cve = matching_positives['CVE-ID'].str.startswith('CVE').any()
        
        if llm_says_has_vulnerability == 1 or llm_says_has_vulnerability == "Yes" or llm_says_has_vulnerability == "True":
            if has_valid_cve:
                TP += 1  # Gültige CVE-ID vorhanden und Schwachstelle bestätigt
            else:
                FP += 1  # Keine gültige CVE-ID, aber Schwachstelle gemeldet
        else:
            if has_valid_cve:
                FN += 1  # Gültige CVE-ID vorhanden, aber keine Schwachstelle gemeldet
                print(f"FN {software} {version}")
            else:
                TN += 1  # Keine gültige CVE-ID und keine Schwachstelle gemeldet
                print(f"TN {software} {version}")
    else:
        if llm_says_has_vulnerability == 1 or llm_says_has_vulnerability == "Yes" or llm_says_has_vulnerability == "True":
            FP += 1  # Falsch positiv, da kein passender Eintrag in der Positivliste gefunden wurde
        else:
            TN += 1  # Wahr negativ, da kein passender Eintrag in der Positivliste gefunden wurde und keine Schwachstelle gemeldet wurde
            print(f"TN {software} {version}")


# Berechnung der Metriken
accuracy = (TP + TN) / (TP + TN + FP + FN) if (TP + TN + FP + FN) > 0 else 0
precision = TP / (TP + FP) if (TP + FP) > 0 else 0
recall = TP / (TP + FN) if (TP + FN) > 0 else 0
f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
mcc_numerator = (TP * TN) - (FP * FN)
mcc_denominator = np.sqrt((TP + FP) * (TP + FN) * (TN + FP) * (TN + FN))
mcc = mcc_numerator / mcc_denominator if mcc_denominator > 0 else 0

# Ausgabe der Ergebnisse
print(f"Confusion Matrix: TP={TP}, FP={FP}, TN={TN}, FN={FN}")
print(f"Accuracy: {accuracy:.4f}, Precision: {precision:.4f}, Recall: {recall:.4f}, F1-Score: {f1_score:.4f}, MCC: {mcc:.4f}")
