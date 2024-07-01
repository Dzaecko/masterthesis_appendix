import csv
import subprocess
from colorama import Fore, Style
import time

# ASCII-Art Startbild mit "Dzaecko"
start_art = """
  ____                     _          
 |  _ \ ______ _  ___  ___| | _____   
 | | | |_  / _` |/ _ \/ __| |/ / _ \  
 | |_| |/ / (_| |  __/ (__|   < (_) | 
 |____//___\__,_|\___|\___|_|\_\___/  
   ____ _     ____            ___   _ 
  / ___| |   / ___| __   __  / _ \ / |
 | |   | |  | |     \ \ / / | | | || |
 | |___| |__| |___   \ V /  | |_| || |
  \____|_____\____|   \_/    \___(_)_|                                                            
"""

print(start_art)  # Display the customized ASCII Art start image

# Define colorful loading text
loading_text = f"{Fore.GREEN}Starting the CVE-LLM-Checker...{Style.RESET_ALL}"

# Animate the loading text
for i in range(30):  # Change the number of repetitions as needed
    loading_text = loading_text[1:] + loading_text[0]  # Move the first character to the end
    print("\r" + loading_text, end="")
    time.sleep(0.2)  # Wait briefly to make the animation visible

print("\n")  # Add a line break to create space for the main output

# Path to the CSV file
csv_file = 'cve150.CSV'
entrys = 150

data_structure = {
    'llama70b': {       
        'True_Software': 0, 'False_Software': 0,
        'True_Version': 0, 'False_Version': 0,
        'True_VulnerabilityType': 0, 'False_VulnerabilityType': 0
    },
    'gpt4': {        
        'True_Software': 0, 'False_Software': 0,
        'True_Version': 0, 'False_Version': 0,
        'True_VulnerabilityType': 0, 'False_VulnerabilityType': 0
    },
    'gpt3': {      
        'True_Software': 0, 'False_Software': 0,
        'True_Version': 0, 'False_Version': 0,
        'True_VulnerabilityType': 0, 'False_VulnerabilityType': 0
    }
}

def calculate_accuracy():
    accuracy_results = {}
    for model, data in data_structure.items():
        accuracy_results[model] = {
            'Software_Accuracy': data['True_Software'] / (data['True_Software'] + data['False_Software']),
            'Version_Accuracy': data['True_Version'] / (data['True_Version'] + data['False_Version']),
            'VulnerabilityType_Accuracy': data['True_VulnerabilityType'] / (data['True_VulnerabilityType'] + data['False_VulnerabilityType'])
        }
    return accuracy_results

def save_accuracy_results_to_file(accuracy_results, filename='accuracy_results.txt'):
    with open(filename, 'w') as file:
        for model, accuracies in accuracy_results.items():
            file.write(f"{model}:\n")
            for key, value in accuracies.items():
                file.write(f"{key}: {value*100:.2f}%\n")
            file.write("\n")
# Funktion zum Umwandeln des Output-Strings in ein Dictionary
def output_to_dict(output):
    output_dict = {}
    for line in output.split('\n'):  # Zerlegt den Output in Zeilen
        if '=' in line:
            key, value = line.split('=', 1)  # Teilt jede Zeile in Key und Value
            output_dict[key.strip().replace(' ', '_')] = value.strip()  # Ersetzt Leerzeichen in Keys durch Unterstriche
    return output_dict

# Funktion zum Aktualisieren der Datenstruktur basierend auf dem Output
def update_data_structure(model, output):
    for key, value in output.items():        
        if key == 'Software':
            data_structure[model]['True_Software' if value == 'Yes' else 'False_Software'] += 1
        elif key == 'Version':
            data_structure[model]['True_Version' if value == 'Yes' else 'False_Version'] += 1
        elif key == 'Vulnerability type':
            data_structure[model]['True_VulnerabilityType' if value == 'Yes' else 'False_VulnerabilityType'] += 1


          
# Öffnen Sie die CSV-Datei und durchlaufen Sie die Zeilen
with open(csv_file, 'r', newline='') as file:
    csv_reader = csv.reader(file, delimiter=';')  # Specify the delimiter as a semicolon
    next(csv_reader)  # Skip the header row if it exists
    for row in csv_reader:
        cve_name = row[0].split(';')[0]  # Extract the first element before the semicolon
        # Start the other Python program and send the CVE name as an argument
        #result = subprocess.run(['python', 'llama70B.py', cve_name], stdout=subprocess.PIPE, text=True)
        result = subprocess.run(['python', 'gpt4withData.py', cve_name], stdout=subprocess.PIPE, text=True)
        output = result.stdout.strip()  # gpt4withData the output of the second program
        print(f"{Fore.CYAN}gpt4withData: {Fore.MAGENTA}{cve_name}{Style.RESET_ALL}: {output}")
        print(f"{Fore.GREEN}verified cve {Fore.YELLOW}{row}{Style.RESET_ALL}")        

        result = subprocess.run(['python', 'compareWithGPT35.py', str(output), str(row)], stdout=subprocess.PIPE, text=True)
        output = result.stdout.strip()  # Capture the output of the other script
        print("*" * 80)  # Füge eine Zeile aus Sternchen hinzu, um die Ausgabe zu trennen
        print(output)
        print("*" * 80)
        # Umwandeln des Output-Strings in ein Dictionary
        output_dict = output_to_dict(output)
        
        # Aktualisieren der Datenstruktur mit dem umgewandelten Dictionary
        model = 'llama70b'  # Beispiel-Modell, das aktualisiert werden soll
        update_data_structure(model, output_dict)
        
      
        # Druckt das aktualisierte Dictionary zum Überprüfen
        print(data_structure[model])
       
    accuracy_results = calculate_accuracy()
    save_accuracy_results_to_file(accuracy_results)
      # Beispiel: Berechnung für das Modell 'llama70b'
     

