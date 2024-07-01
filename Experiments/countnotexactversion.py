import os
import json

def check_json_files(directory):
    total_files = 0
    files_containing_keywords = 0
    keywords = ["before", "after", "up to", "earlier", "lessThan", "or prior"]

    # Durchläuft alle Dateien im angegebenen Verzeichnis
    for filename in os.listdir(directory):
        if filename.endswith('.json'):
            total_files += 1
            path = os.path.join(directory, filename)
            contains_keyword = False

            with open(path, 'r', encoding='utf-8') as file:
                try:
                    data = json.load(file)
                    text = json.dumps(data)  # Konvertiert die JSON-Daten in einen String
                except json.JSONDecodeError as e:
                    print(f"Error decoding JSON from {filename}: {e}")
                    continue  # Springt zur nächsten Datei, falls eine nicht lesbar ist
                
                # Überprüft, ob einer der Schlüsselwörter im Text vorkommt
                for keyword in keywords:
                    if keyword in text:
                        contains_keyword = True
                        break

            if contains_keyword:
                files_containing_keywords += 1

    # Berechnet Statistiken
    percent_with_keywords = (files_containing_keywords / total_files) * 100 if total_files > 0 else 0

    return {
        "total_files": total_files,
        "files_with_keywords": files_containing_keywords,
        "percent_with_keywords": percent_with_keywords
    }

# Pfad zum Verzeichnis
path_to_directory = r'C:\Users\Dzaecko\Downloads\cvelistV5-main\cvelistV5-main\cvelist'
results = check_json_files(path_to_directory)
print(results)
