import os
import random
import pandas as pd
import openai
import re
import json

endpoint = "https://agilecopilot1.openai.azure.com/"
api_key = "4e87e184a87346eda3fb015436357b99"
deployment = "userstory"

def select_random_files(directory, n=500):
    """Wählt n zufällige Dateien aus einem Verzeichnis aus, die mit 'CVE' beginnen."""
    files = [os.path.join(directory, f) for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f)) and f.startswith("CVE")]
    selected_files = random.sample(files, min(len(files), n))
    return selected_files

def process_files(files):
    """Verarbeitet die Dateien und ruft das OpenAI-Modell für jede Datei auf.
    Überspringt Einträge, bei denen 'Software' nicht vorhanden ist."""
    results = []
    for file_path in files:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
            response = openai_call(content)
            # Überprüfen, ob 'Software' im Antwort-JSON vorhanden ist
            if 'Software' in response and response['Software']:
                result = {
                    "Software": response['Software'],
                    "Version": response['Version'],
                    "VulnerabilityType": response['VulnerabilityType'],
                    "CVE-ID": response['CVE-ID'],
                }
                results.append(result)
            if 'ProblemTypes' in response:
                    result['ProblemTypes'] = response['ProblemTypes']
            if 'Metrics' in response:
                    result['Metrics'] = response['Metrics']
            if 'Score' in response:
                    result['Score'] = response['Score']
            if 'CWE-ID' in response:
                    result['CWE-ID'] = response['CWE-ID']
            else:
                print(f"Eintrag in {file_path} übersprungen, da 'Software' nicht vorhanden ist.")
    return results


def openai_call(content):
    """Führt einen OpenAI-API-Aufruf durch. Implementieren Sie diese Funktion entsprechend."""
    # Beispiel für einen API-Aufruf (ersetzen Sie YOUR_API_KEY mit Ihrem tatsächlichen API-Schlüssel)
    client = openai.AzureOpenAI(
    base_url=f"{endpoint}/openai/deployments/{deployment}",
    api_key=api_key,
    api_version="2023-08-01-preview",
    )
    completion = client.chat.completions.create(
    model=deployment,
    messages=[
        {
            "role": "user",
            "content": (
    f'"content": "{content}. Provide me the information from this text in that json format: '
    '{"Software": "<software_name>", "Version": "<version_number>", "VulnerabilityType": "<vulnerability_type>"}.", "CVE-ID": "<cveId>", "Metrics": "<metrics>", "Score": "<score>", "CWE-ID": "<cweId>", "ProblemTypes": "<problemTyps>"}."'
)
        },
    ],       
    temperature=0,
    top_p=1,
    max_tokens=800,  
)

# Verwenden von Regular Expressions, um das JSON-Objekt zu finden
    json_match = re.search(r'\{.*?\}', completion.choices[0].message.content, re.DOTALL)

    if json_match:
        json_str = json_match.group(0)
        json_data = json.loads(json_str)
        print(json_data)
        return json_data
    else:
        print("Kein JSON gefunden.")
        # Beispielantwort, diese muss durch die tatsächliche Antwort ersetzt werden
        

def save_to_json(data, filename_prefix="positiveList"):
    """Speichert die Daten in einer JSON-Datei, benannt nach der Anzahl der enthaltenen Elemente."""
    filename = f"{filename_prefix}_{len(data)}.json"
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)
    print(f"Daten wurden in {filename} gespeichert.")

directory = "C:\\Users\\Dzaecko\\source\\repos\\MasterThesisScripts\\docs"
files = select_random_files(directory)
results = process_files(files)
save_to_json(results)
