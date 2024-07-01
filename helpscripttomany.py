import json

# Pfad zur Eingabe-JSON-Datei
input_file = 'positiveList_145.json'

# Die Daten aus der Eingabe-JSON-Datei lesen
with open(input_file, 'r', encoding='utf-8') as file:
    data = json.load(file)

# Iterieren durch jedes Element in der Liste
for item in data:
    # Erstellen des Dateinamens basierend auf Softwarenamen und Version
    # Zeichen, die möglicherweise ungültig für Dateinamen sind, werden durch "_" ersetzt.
    filename = f"{item['Software'].replace(' ', '_').replace('/', '_')}-{item['Version']}.json"
    
    # Speichern der Daten in einer JSON-Datei
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(item, f, ensure_ascii=False, indent=4)
        
    print(f"Datei {filename} wurde erstellt.")
