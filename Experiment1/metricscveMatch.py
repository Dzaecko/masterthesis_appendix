import pandas as pd
import numpy as np

# Pfad zu Ihrer CSV- und JSON-Datei
csv_file_path = 'results_llama_70b.csv'
json_file_path = 'positiveList_479.json'

# Einlesen der Daten
df_results = pd.read_csv(csv_file_path, delimiter=';')
df_positives = pd.read_json(json_file_path)

# Initialisierung der Metriken
TP = FP = TN = FN = 0

# Funktion zur Überprüfung der CVE-ID Übereinstimmung
def check_cve_id_match(result_cve_ids, positive_cve_ids):
    result_cve_ids_set = set(result_cve_ids.split(', ')) if result_cve_ids != "n/a" else set()
    positive_cve_ids_set = set(positive_cve_ids) if isinstance(positive_cve_ids, list) else {positive_cve_ids}
    return not result_cve_ids_set.isdisjoint(positive_cve_ids_set)

# Überprüfung auf Übereinstimmungen
for _, row in df_results.iterrows():
    software = row['Software']
    version = row['Version']
    result_cve_ids = str(row['LLMsaysThisCVEId'])
    
    matching_positives = df_positives[(df_positives['Software'] == software) & 
                                      (df_positives['Version'].astype(str).str.contains(version, regex=False))]

    has_cve_in_result = result_cve_ids != "n/a" and "CVE-" in result_cve_ids

    if not matching_positives.empty:
        positive_cve_ids = matching_positives['CVE-ID'].explode().dropna().unique().tolist()
        if any(check_cve_id_match(result_cve_ids, cve_id) for cve_id in positive_cve_ids):
            TP += 1
        elif has_cve_in_result:
            FP += 1
        else:
            FN += 1
    else:
        if has_cve_in_result:
            FP += 1
        else:
            TN += 1

# Berechnung des Matthews Korrelationskoeffizienten (MCC)
mcc_numerator = (TP * TN) - (FP * FN)
mcc_denominator = np.sqrt((TP + FP) * (TP + FN) * (TN + FP) * (TN + FN))
MCC = mcc_numerator / mcc_denominator if mcc_denominator > 0 else 0

# Ausgabe der Ergebnisse
print(f"Confusion Matrix: TP={TP}, FP={FP}, TN={TN}, FN={FN}")
print(f"Accuracy: {(TP + TN) / (TP + TN + FP + FN):.4f}")
print(f"Precision: {TP / (TP + FP) if TP + FP > 0 else 0:.4f}")
print(f"Recall: {TP / (TP + FN) if TP + FN > 0 else 0:.4f}")
print(f"F1-Score: {2 * ((TP / (TP + FP) if TP + FP > 0 else 0) * (TP / (TP + FN) if TP + FN > 0 else 0)) / ((TP / (TP + FP) if TP + FP > 0 else 0) + (TP / (TP + FN) if TP + FN > 0 else 0)) if ((TP / (TP + FP) if TP + FP > 0 else 0) + (TP / (TP + FN) if TP + FN > 0 else 0)) > 0 else 0:.4f}")
print(f"MCC: {MCC:.4f}")
