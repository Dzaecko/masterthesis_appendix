import numpy as np
import pandas as pd

# Daten laden
data = pd.read_csv('resultsgpt330350n.csv', encoding='ISO-8859-1', delimiter=';')
y_pred = data['LLMSaysIsAffected'].values
y_true = data['LLMTrue'].values

# Berechnung der Confusion Matrix direkt
TP = np.sum((y_pred == "WAHR") & (y_true == "WAHR"))
FP = np.sum((y_pred == "WAHR") & (y_true == "FALSCH"))
FN = np.sum((y_pred == "FALSCH") & (y_true == "FALSCH"))
TN = np.sum((y_pred == "FALSCH") & (y_true == "WAHR"))

# Metriken berechnen
accuracy = (TP + TN) / (TP + FP + FN + TN) if (TP + FP + FN + TN) > 0 else 0
precision = TP / (TP + FP) if TP + FP > 0 else 0
recall = TP / (TP + FN) if TP + FN > 0 else 0
f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
mcc_numerator = (TP * TN) - (FP * FN)
mcc_denominator = np.sqrt((TP + FP) * (TP + FN) * (TN + FP) * (TN + FN))
mcc = mcc_numerator / mcc_denominator if mcc_denominator != 0 else 0

# Ausgabe der Ergebnisse
print("Confusion Matrix:")
print(f"TP: {TP}, FN: {FN}")
print(f"FP: {FP}, TN: {TN}")
print("Accuracy :", accuracy)
print("Precision :", precision)
print("Recall :", recall)
print("F1-Score:", f1_score)
print("Matthews Korrelationskoeffizient (MCC):", mcc)
