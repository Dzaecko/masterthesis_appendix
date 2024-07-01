import csv

def parse_cve_data(input_file, output_file):
    with open(input_file, 'r') as f:
        reader = csv.reader(f)
        next(reader)  # Überspringen der Kopfzeile
        next(reader)  # Überspringen der Trennzeile
        next(reader)  # Überspringen der Spaltenbeschreibung
        cve_list = []
        for row in reader:
            if len(row) < 3:
                continue
            cve_name = row[0]
            cve_status = row[1]
            cve_description = row[2]
            cve_list.append((cve_name, cve_status, cve_description))

    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Name', 'Status', 'Description'])
        for cve in cve_list:
            writer.writerow(cve)

parse_cve_data('input.csv', 'output.csv')
