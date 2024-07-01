import json
from fuzzywuzzy import fuzz
import sys
import ast

cvellm = sys.argv[1]
cveorig = sys.argv[2]

def match_values_with_improved_logic(json_input, text):
    try:
        data = ast.literal_eval(json_input)
    except ValueError as e:
        print(f"Fehler beim Parsen des JSON-Inputs: {e}")
        return 0
    
    text_lower = text.lower()
    matched_values = 0
    total_values = 1  # Da wir nur einen spezifischen Wert berücksichtigen

    # Verarbeite nur den Wert für den Schlüssel 'VulnerabilityType'
    value = data.get('VulnerabilityType', '')
    if value:
        val_lower = value.lower()
        if val_lower in text_lower:
            matched_values += 1
        else:
            match_score = fuzz.partial_ratio(val_lower, text_lower)
            if match_score > 60:  # Angenommener Schwellenwert für eine akzeptable Ähnlichkeit
                matched_values += 1
    else:
        return 0  # Kein 'VulnerabilityType' im JSON

    detection_rate = matched_values / total_values
    return detection_rate

# Beispiel-JSON und Text
json_input = cvellm
text = cveorig

# Ausführung der Funktion und Ausgabe des Ergebnisses
detection_rate = match_values_with_improved_logic(json_input, text)
print(detection_rate)
