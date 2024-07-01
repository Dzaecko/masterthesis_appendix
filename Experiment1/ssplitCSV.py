import os

def split_csv(input_file_path, output_folder, max_size=60000):
    # Stelle sicher, dass das Ausgabeverzeichnis existiert
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    
    # Kopfzeile, die in jede Datei geschrieben werden soll
    header = 'id,file,description,date_published,author,type,platform,port,date_added,date_updated,verified,codes,tags,aliases,screenshot_url,application_url,source_url\n'
    
    # Zähler für die Ausgabedateien
    file_number = 1
    
    # Initialisiere Variablen für die aktuelle Dateigröße und den Inhalt
    current_size = len(header)
    current_content = header
    
    # Öffne die Eingabedatei
    with open(input_file_path, 'r', encoding='ISO-8859-1') as file:
        next(file)  # Überspringe die Kopfzeile
        for line in file:
            line_size = len(line)
            # Wenn das Hinzufügen der Zeile die maximale Größe überschreitet, schreibe die aktuelle Datei und starte eine neue
            if current_size + line_size > max_size:
                with open(f'{output_folder}/exploitdbsplit_{file_number}.csv', 'w', encoding='ISO-8859-1') as output_file:
                    output_file.write(current_content)
                file_number += 1
                current_content = header + line
                current_size = len(header) + line_size
            else:
                current_content += line
                current_size += line_size
    
    # Schreibe den letzten Dateiinhalt, wenn noch nicht geschehen
    if current_content != header:
        with open(f'{output_folder}/exploitdbsplit_{file_number}.csv', 'w', encoding='ISO-8859-1') as output_file:
            output_file.write(current_content)

# Setze hier den Pfad zur CSV-Datei und den Zielordner für die aufgeteilten Dateien
input_file_path = 'files_exploits.csv'
output_folder = 'C:\\Users\\Dzaecko\\source\\repos\\MasterThesisScripts\\exploitdb'
split_csv(input_file_path, output_folder)
