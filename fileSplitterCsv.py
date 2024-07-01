import os
import csv

# Parameter
max_size_bytes = 12 * 1024 * 1024  # 12 MB
max_characters = 65000
output_folder = 'outputcsvall'
input_csv = 'allitems.csv'  # Ändern Sie dies zu Ihrem Dateinamen

# Ordner erstellen, falls nicht vorhanden
if not os.path.exists(output_folder):
    os.makedirs(output_folder)

def split_csv(input_csv, output_folder, max_size_bytes, max_characters):
    file_index = 1
    current_size = 0
    current_chars = 0
    output_file_path = os.path.join(output_folder, f'output_{file_index}.txt')
    output_file = open(output_file_path, 'w', encoding='utf-8')

    with open(input_csv, 'r', encoding='iso-8859-1') as csv_file:
        reader = csv.reader(csv_file)
    
        for row in reader:
            row_string = ','.join(row) + '\n'
            row_size = len(row_string.encode('utf-8'))
            row_chars = len(row_string)
            
            if current_size + row_size > max_size_bytes or current_chars + row_chars > max_characters:
                # Datei schließen und neue Datei öffnen
                output_file.close()
                file_index += 1
                output_file_path = os.path.join(output_folder, f'output_{file_index}.txt')
                output_file = open(output_file_path, 'w', encoding='utf-8')
                current_size = 0
                current_chars = 0

            output_file.write(row_string)
            current_size += row_size
            current_chars += row_chars

    output_file.close()

# Funktion mit den definierten Parametern aufrufen
split_csv(input_csv, output_folder, max_size_bytes, max_characters)
