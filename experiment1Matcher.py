import pandas as pd
import json

def main(csv_file_path, json_file_path):
    # CSV-Datei laden
    csv_data = pd.read_csv(csv_file_path, delimiter=';')

    # JSON-Datei laden
    with open(json_file_path, 'r') as file:
        json_data = json.load(file)

    # Zähler für nicht gefundene Einträge
    not_found_count = 0

    # Ergebnisse speichern
    results = []

    # Durch die JSON-Liste iterieren und mit CSV vergleichen
    for entry in json_data:
        found_match = False
        # Iteriere durch jede Version in der JSON-Liste
        for version in entry['Version']:
            # Suche nach passendem Eintrag in der CSV
            matching_entry = csv_data[
                (csv_data['Software'].str.lower() == entry['Software'].lower()) &
                (csv_data['Version'].str.contains(version, case=False, regex=False))
            ]
            
            # Wenn ein passender Eintrag gefunden wurde, bearbeite ihn und breche die innere Schleife ab
            if not matching_entry.empty:
                software = matching_entry.iloc[0]['Software']
                version = matching_entry.iloc[0]['Version']
                vulnerability_csv = matching_entry.iloc[0]['LLMSaysHasThisVulnerability']
                cve_id_csv = matching_entry.iloc[0]['LLMsaysThisCVEId']
                
                # Die Vergleichsfunktion aufrufen und Ergebnis speichern
                results.append({
                    'software': software,
                    'version': version,
                    'vulnerability_csv': vulnerability_csv,
                    'cve_id_csv': cve_id_csv
                })
                found_match = True
                break  # Ein passender Eintrag wurde gefunden, keine Notwendigkeit, weitere Versionen zu prüfen

        if not found_match:
            # Zähler erhöhen, wenn kein Eintrag für keine der Versionen gefunden wurde
            not_found_count += 1

    # Ergebnisse und Zähler ausgeben
    print(f"Anzahl nicht gefundener Einträge: {not_found_count}")
    for result in results:
        print(result)

# Pfad zu Ihren Dateien
csv_file_path = 'ergebnissegpt4.csv'
json_file_path = 'positiveList_145.json'

# Die main-Funktion aufrufen
if __name__ == '__main__':
    main(csv_file_path, json_file_path)
