import csv


# Pfad der Quelldatei
input_file_path =  'cve150.csv'
# Pfad der Zieldatei
output_file_path = 'cve150inonesentence.csv'

# Öffnen der Quelldatei im Lese-Modus
with open(input_file_path, mode='r', encoding='utf-8') as infile:
    # Öffnen der Zieldatei im Schreib-Modus
    with open(output_file_path, mode='w', newline='', encoding='utf-8') as outfile:
        # Erstellen eines csv.reader, um die Zeilen zu lesen
        reader = csv.DictReader(infile, delimiter=';')

        # Erstellen eines csv.writer, um die Zeilen zu schreiben
        writer = csv.writer(outfile)
        
        # Schreiben der Spaltenüberschrift in die Zieldatei
        writer.writerow(['Modified Description'])  # Nur eine Spalte für modifizierte Beschreibungen
        
        # Durchgehen jeder Zeile in der Quelldatei
        for row in reader:
            # Erstellen der modifizierten Beschreibung
            modified_description = f"{row['Name']} is the cve id for this vulnerability: {row['Description']}"
            
            # Schreiben der modifizierten Beschreibung in die Zieldatei
            writer.writerow([modified_description])