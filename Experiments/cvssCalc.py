import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report, matthews_corrcoef
import seaborn as sns
import matplotlib.pyplot as plt

# Datei einlesen
df = pd.read_csv('output_cvss_data3.csv')
# Tatsächliche und vorhergesagte Werte extrahieren

def parse_cvss_vector(vector):
    vector = vector.replace('CVSS:3.1/', '')
    components = vector.split('/')
    return {comp.split(':')[0]: comp.split(':')[1] for comp in components}

metrics = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']  # Die Metriken

accuracy_scores = {}
confusion_matrices = {}
mcc_scores = {}
# Berechnung der Confusion Matrix für alle Kategorien

# Berechnen der Konfusionsmatrizen, Genauigkeitswerte, Bewertungsberichte und MCC
for metric in metrics:
    df['Predicted_' + metric] = df['Generated Vector String'].apply(lambda x: parse_cvss_vector(x)[metric])
    df['Original_' + metric] = df['Original Vector String'].apply(lambda x: parse_cvss_vector(x)[metric])
    
    # Berechnung der Genauigkeit, Konfusionsmatrix und MCC
    accuracy_scores[metric] = accuracy_score(df['Original_' + metric], df['Predicted_' + metric])
    confusion_matrices[metric] = confusion_matrix(df['Original_' + metric], df['Predicted_' + metric])
    mcc_scores[metric] = matthews_corrcoef(df['Original_' + metric], df['Predicted_' + metric])
    
    # Ausgabe der Konfusionsmatrix
    print(f"Confusion Matrix für {metric}:")
    # sns.heatmap(confusion_matrices[metric], annot=True)
    # plt.title(f'Confusion Matrix for {metric}')
    # plt.xlabel('Predicted')
    # plt.ylabel('Actual')
    # plt.show()
    
    # Ausgabe des Bewertungsberichts
    print(classification_report(df['Original_' + metric], df['Predicted_' + metric]))

df['Original Severity'] = df['Original Severity'].str.lower()
df['Calculated Severity'] = df['Calculated Severity'].str.lower()

# Berechnen der Übereinstimmungsrate für Severity
severity_accuracy = accuracy_score(df['Original Severity'], df['Calculated Severity'])

# Ausgabe der Prädiktiven Genauigkeitswerte für jede CVSS-Metrik
print("Prädiktive Genauigkeitswerte für jede CVSS-Metrik:")
for metric, score in accuracy_scores.items():
    print(f"{metric}: {score:.2f}")

# Ausgabe der Matthews-Korrelation (MCC) für jede CVSS-Metrik
print("Matthews-Korrelationskoeffizienten (MCC) für jede CVSS-Metrik:")
for metric, score in mcc_scores.items():
    print(f"{metric}: {score:.2f}")

print(f"Übereinstimmungsrate für Severity: {severity_accuracy:.2f}")

# Optional: Ergebnisse in eine neue CSV-Datei speichern
# df.to_csv('/path/to/output_accuracy_results.csv', index=False)
