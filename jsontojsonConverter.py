import json
import os

# Pfad zum Ordner mit den JSON-Dateien
input_directory = 'docs'
output_file_path = 'finetuning.jsonl'

# Funktion, um die notwendigen Informationen zu extrahieren und zu formatieren
def get_nested_value(d, keys, default=None):
    """
    Versucht, einen verschachtelten Wert aus einem Dictionary abzurufen,
    basierend auf einer Liste von Schlüsseln.
    """
    assert isinstance(keys, list), "keys must be provided as a list"
    for key in keys:
        try:
            d = d[key]
        except KeyError:
            return default
    return d

def format_entry(entry):
    # Verwenden der neuen Funktion, um sicher auf die Beschreibung zuzugreifen
    descriptions = get_nested_value(entry, ["containers", "cna", "descriptions"], [])
    # Findet die englische Beschreibung, falls vorhanden
    description = next((desc["value"] for desc in descriptions if desc.get("lang") == "en"), "")
    cve_id = get_nested_value(entry, ["cveMetadata", "cveId"], "Unknown CVE-ID")

    return {
        "messages": [
            {
                "role": "system",
                "content": "This system provides detailed information and analysis on CVE security vulnerabilities."
            },
            {
                "role": "user",
                "content": f"What is {cve_id}?"
            },
            {
                "role": "assistant",
                "content": description
            }
        ]
    }

# Öffnen (oder erstellen) der Ausgabedatei
with open(output_file_path, 'w', encoding='utf-8') as output_file:
    # Iteration durch alle Dateien im angegebenen Verzeichnis
    for filename in os.listdir(input_directory):
        if filename.endswith('.json'):  # Sicherstellen, dass es eine JSON-Datei ist
            file_path = os.path.join(input_directory, filename)
            with open(file_path, 'r', encoding='utf-8') as file:  # Hier die Kodierung angeben
                data = json.load(file)
                formatted_entry = format_entry(data)
                # Schreiben der strukturierten Daten als JSON-String in die Datei, gefolgt von einem Zeilenumbruch
                json_string = json.dumps(formatted_entry, ensure_ascii=False)
                output_file.write(json_string + '\n')

print("Data has been successfully transformed and saved.")
