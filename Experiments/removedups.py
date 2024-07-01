import pandas as pd

# Dateiname der Eingabedatei
input_filename = 'results_mistral.csv'
# Dateiname der Ausgabedatei
output_filename = 'results_mistral_clean.csv'

# Lade die Daten
data = pd.read_csv(input_filename, delimiter=';')

# Entferne Duplikate basierend auf den Spalten 'Software' und 'Version'
# Behalte jeweils den ersten Eintrag bei Duplikaten
cleaned_data = data.drop_duplicates(subset=['Software', 'Version'], keep='first')

# Speichere die bereinigten Daten in einer neuen Datei
cleaned_data.to_csv(output_filename, index=False, sep=';')

print("Duplikate wurden entfernt und die Daten wurden gespeichert in:", output_filename)
