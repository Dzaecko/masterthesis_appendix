import os
import random
import pandas as pd
import openai
import re
import json

endpoint = "https://agilecopilot1.openai.azure.com/"
api_key = "4e87e184a8XXX36357b99"
deployment = "userstory"
files_without_json_count = 0

def select_random_files(directory, n=500):   
    files = [os.path.join(directory, f) for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f)) and f.startswith("CVE")]
    selected_files = random.sample(files, min(len(files), n))
    return selected_files

def select_non_cve_files(directory, n=200):    
    files = [os.path.join(directory, f) for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f)) and not f.startswith("CVE")]
    return random.sample(files, min(len(files), n))

def process_selected_files(files):   
    results = []
    for file_path in files:
        with open(file_path, 'r', encoding='utf-8') as file:
            try:
                content = json.load(file)
                # Nur 'Software' und 'Version' werden übernommen, andere Werte werden mit 'None' befüllt
                result = {
                    "Software": content.get("Software", "None"),
                    "Version": content.get("Version", "None"),
                    "VulnerabilityType": "None",
                    "CVE-ID": "None",
                    # Fügen Sie hier weitere Felder ein, die auf 'None' gesetzt werden sollen
                }
                results.append(result)
            except json.JSONDecodeError:
                print(f"Fehler beim Lesen von {file_path}. Überspringen.")
    return results

def process_non_cve_files_and_save(directory, output_filename="non_cve_results.json"):
    files = select_non_cve_files(directory)
    results = process_selected_files(files)
    save_results_to_json(results, output_filename)

def save_results_to_json(data, filename):
    """Speichert die Ergebnisse in einer JSON-Datei."""
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)
    print(f"Daten wurden in {filename} gespeichert.")

def process_files(files):
    """Verarbeitet die Dateien und ruft das OpenAI-Modell für jede Datei auf.
    Überspringt Einträge, bei denen 'Software' nicht vorhanden ist."""
    global files_without_json_count  
    results = []
    for file_path in files:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
            response = openai_call(content)
            if response:  
                result = {
                    "Software": response.get("Software", "None"),
                    "Version": response.get("Version", "None"),
                    "VulnerabilityType": response.get("VulnerabilityType", "None"),
                    "CVE-ID": response.get("CVE-ID", "None"),
                    "ProblemTypes": response.get("ProblemTypes", "None"),
                    "Metrics": response.get("Metrics", "None"),
                    "Score": response.get("Score", "None"),
                    "CWE-ID": response.get("CWE-ID", "None"),
                }
                results.append(result)
            else:
                files_without_json_count += 1
    return results

def openai_call(content):
    
    global files_without_json_count
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

    try:            
            full_response_content = completion.choices[0].message.content
            json_match = re.search(r'\{.*?\}\s*$', full_response_content, re.DOTALL)
            if json_match:
                json_str = json_match.group(0)
                json_data = json.loads(json_str)
                print(json_data)
                return json_data
            else:
                print("Kein korrektes JSON gefunden.")
                return None
    except json.JSONDecodeError as e:
            print(f"JSONDecodeError: {e}.")            
            return None
    except Exception as e:
            print(f"Unknown Error: {e}")
            return None
        

def save_to_json(data, filename_prefix="positiveList"):    
    filename = f"{filename_prefix}_{len(data)}.json"
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)
    print(f"Daten wurden in {filename} gespeichert.")

directory = "C:\\Users\\Dzaecko\\source\\repos\\MasterThesisScripts\\docs"
process_non_cve_files_and_save(directory)
files = select_random_files(directory)
results = process_files(files)
save_to_json(results)
print(f"Anzahl der Dateien ohne gefundenem JSON: {files_without_json_count}")