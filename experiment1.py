import json
import subprocess
import os
from pathlib import Path

import os
import json
from callLLM import TextGenerator
import logging
import sys
import re
import time
import subprocess
from openai import AzureOpenAI
import ssl
import sys
import ast
from llama_index.embeddings.openai import OpenAIEmbedding
from llama_index.llms.openai import OpenAI
import csv
import urllib.request

from llama_index.core.callbacks import CallbackManager
from llama_index.core import (
    VectorStoreIndex,
    SimpleDirectoryReader,
    StorageContext,
    load_index_from_storage,
)


def allowSelfSignedHttps(allowed):
    # Bypass der Zertifikatsüberprüfung auf Clientseite
    if allowed and not os.environ.get('PYTHONHTTPSVERIFY', '') and getattr(ssl, '_create_unverified_context', None):
        ssl._create_default_https_context = ssl._create_unverified_context

allowSelfSignedHttps(True) # Diese Zeile ist erforderlich, wenn Sie ein selbstsigniertes Zertifikat in Ihrem Scoring-Service verwenden.

def read_from_storage(persist_dir):
    storage_context = StorageContext.from_defaults(persist_dir=persist_dir)
    return load_index_from_storage(storage_context)

def process_data(software, version, index):
    #llm = OpenAI(model="ft:gpt-3.5-turbo-1106:personal::8wAcu91u")
    llm = OpenAI(model="gpt-4-turbo-preview")
    query_engine = index.as_query_engine(llm=llm)
    # response = query_engine.query(f'Are there any known vulnerabilities in {software} {version}? Tell me the CVE Number. If so, what are they? also check the version specifically for the context. For example, there is no vulnerability in version 1.8 if the text says before 1.8. If such a case occurs, do not answer me as json but describe why there may not be a vulnerability. Please provide the JSON data for cve_number with the following format: {{"Software": "<software_name>", "Version": "<version_number>", "VulnerabilityType": "<vulnerability_type>", "CVE-ID": "<cveId>"}}.')
    response = query_engine.query(f'Are there any known vulnerabilities in {software} {version}? Also check the version specifically for the context. For example, there is no vulnerability in version 1.8 if the text says before 1.8. Please provide the JSON data for cve_number with the following format: {{"HasVulnerability": "<has_vulnerability>", "VulnerabilityTypes": "<vulnerability_type>", "CVE-IDs": "<cve_id>", "PossibleAffectedVersions": "<poa_versions>"}}.')
   
    print(response)
    return response
    json_match = re.search(r'\{.*?\}', response, re.DOTALL)
    if json_match:
        json_str = json_match.group(0)
        json_data = json.loads(json_str)
        print(json_data)
        return response
    else:
        print("Kein JSON gefunden.")
        return None
    
def process_dataLLama(software, version, index):
    data =  {
    "messages": [
        {
        "role": "user",
            "content": (f'"Are there any known vulnerabilities in {software} {version}? Please provide the JSON data for cve_number with the following format: {{"HasVulnerability": "<has_vulnerability>", "VulnerabilityTypes": "<vulnerability_type>", "CVE-IDs": "<cve_id>", "PossibleAffectedVersions": "<poa_versions>"}}.'
            '{"Software": "<software_name>", "Version": "<version_number>", "VulnerabilityType": "<vulnerability_type>"}." ')   
        },
    
    ],
    "temperature": 0.8,
    "max_tokens": 500
    }

    body = str.encode(json.dumps(data))

    url = 'https://Llama-2-70b-chat-svbxh-serverless.westus3.inference.ai.azure.com/v1/chat/completions'
    # Ersetzen Sie dies durch den primären/sekundären Schlüssel oder AMLToken für den Endpunkt
    api_key = 'njkWUo4K14ajVIjpRIR5ZsOqhwqy3f9a'
    if not api_key:
        raise Exception("A key should be provided to invoke the endpoint")

    headers = {'Content-Type':'application/json', 'Authorization':('Bearer '+ api_key)}

    req = urllib.request.Request(url, body, headers)

    try:
        response = urllib.request.urlopen(req)

        result = response.read().decode('utf-8')  # Decodieren der Antwort in einen String
        result_json = json.loads(result)  # Parsen des Strings in ein JSON-Objekt
        
        # Zugreifen auf den 'content' Teil im 'assistant'
        #content = result_json['choices'][0]['message']['content']
        #print(content)
        json_match = re.search(r'\{.*?\}', result_json['choices'][0]['message']['content'], re.DOTALL)       
        #return completion.choices[0].message.content
        if json_match:
            json_str = json_match.group(0)
            json_data = try_parse_json(json_str)     
            print(json_data)
            return json_data
        else:
            print("Kein JSON gefunden.")
    except urllib.error.HTTPError as error:
        print("The request failed with status code: " + str(error.code))

        # Drucken Sie die Header aus, sie enthalten die Anforderungs-ID und den Zeitstempel, die für die Fehlerbehebung der Fehler nützlich sind
        print(error.info())
        print(error.read().decode("utf8", 'ignore'))

    
def process_dataAzureOpenAI(software, version, index):
    endpoint = "https://agilecopilot1.openai.azure.com"
    api_key = "4e87e184a87346eda3fb015436357b99"
    deployment = "userstory"

    client = AzureOpenAI(
        base_url=f"{endpoint}/openai/deployments/{deployment}/extensions",
        api_key=api_key,
        api_version="2023-09-01-preview",
    )

   

    completion = client.chat.completions.create(
        model=deployment,
        messages=[
            {
                "role": "user",
                "content": (f'"Are there any known vulnerabilities in {software} {version}? Please provide the JSON data for cve_number with the following format: {{"HasVulnerability": "<has_vulnerability>", "VulnerabilityTypes": "<vulnerability_type>", "CVE-IDs": "<cve_id>", "PossibleAffectedVersions": "<poa_versions>"}}.'
        '{"Software": "<software_name>", "Version": "<version_number>", "VulnerabilityType": "<vulnerability_type>"}." ')      
            },
        ],
        extra_body={
            "dataSources": [
                {
                    "type": "AzureCognitiveSearch",
                    "parameters": {
                        "endpoint": "https://searchdzaeck.search.windows.net",
                        "key": "I41ZLKbe23y85Ikvs5pGU4qTNJ8hXrglLDfKxNnTlSAzSeBERxZ5",
                        "queryType": "vectorSemanticHybrid",
                        "semanticConfiguration" : "vector-1711903315614-cve4000neu4000-semantic-configuration",
                        "fieldsMapping": {},
                        "inScope": "true",                 
                        "strictness": 3,
                        "topNDocuments": 5,
                        "roleInformation": "You are a helpful assistant.  ",
                        "indexName": "vector-1711903315614-cve4000neu4000",
                        "embeddingDeploymentName": "ada2"
                    }
                }
            ]        
        }, 
    
        temperature=0,
        top_p=1,
        max_tokens=800,  
    )

    # Verwenden von Regular Expressions, um das JSON-Objekt zu finden
    json_match = re.search(r'\{.*?\}', completion.choices[0].message.content, re.DOTALL)
    print(completion.choices[0].message.content)
    #return completion.choices[0].message.content
    if json_match:
        json_str = json_match.group(0)
        json_data = try_parse_json(json_str)     
        print(json_data)
        return json_data
    else:
        print("Kein JSON gefunden.")

def try_parse_json(json_str):
    try:
        # Versucht den JSON-String zu parsen
        json_data = json.loads(json_str)
        print("Geparstes JSON:", json_data)
        return json_data
    except json.JSONDecodeError as e:
        # Gibt eine spezifische Fehlermeldung aus
        print(f"Fehler beim Parsen des JSON-Strings: {e}")
        # Hier könnten Sie versuchen, den String zu reparieren und erneut zu parsen
        # Für dieses Beispiel geben wir nur den Fehler zurück
        return None
    except Exception as e:
        print(f"Unbekannter Fehler: {e}")
        return None
    
def load_cve_details(csv_file_path, cve_id):
    with open(csv_file_path, mode='r', encoding='ISO-8859-1') as csvfile:
        csv_reader = csv.DictReader(csvfile, delimiter=';')
        for row in csv_reader:
            row = {k.strip(): v.strip() for k, v in row.items()}
            if row['Name'] == cve_id:
                return row
    return None

def main(json_file_path, csv_file_path):
    persist_dir = "./storage"
    index = read_from_storage(persist_dir)
    true_positives = []
    total_entries = 0

    with open(json_file_path, 'r') as file:
        data = json.load(file)

# Vor der Schleife: Öffne die CSV-Datei zum Schreiben
    with open('ergebnissellamaindex_neu.csv', mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file, delimiter=';')
        # Schreibe die Header-Zeile in die CSV-Datei
        writer.writerow(['Software', 'Version', 'LLMSaysHasVulnerability', 'LLMSaysHasThisVulnerability', 'LLMsaysThisCVEId', 'PossibleAffectedVersions'])
    
        for row in data:
            software = row['Software']
            version = row['Version']
            cve_id = row['CVE-ID']
            csv_data = 1#load_cve_details(csv_file_path, cve_id)
            if csv_data:
                processed_data = process_data(software, version, "")
                #generator = TextGenerator(f'Are there any known vulnerabilities in {software} {version}? Also check the version specifically for the context. For example, there is no vulnerability in version 1.8 if the text says before 1.8. Please provide the JSON data for cve_number with the following format: {{"HasVulnerability": "<has_vulnerability>", "VulnerabilityTypes": "<vulnerability_type>", "CVE-IDs": "<cve_id>", "PossibleAffectedVersions": "<poa_versions>"}}. If no data is found, fill the json with zero values. No further description.')

# Rufe die generate_text Methode mit dem LLM-Parameter auf
                #processed_data = generator.generate_text(1)

                if processed_data is not None:
                    # result = subprocess.run([
                    #     'C:\\Users\\Dzaecko\\source\\repos\\MasterThesisScripts\\.venv\\Scripts\\python.exe', 
                    #     'fuzzyMatcher.py', 
                    #     str(processed_data), 
                    #     json.dumps(csv_data)], 
                    #     stdout=subprocess.PIPE, 
                    #     text=True)
                    
                    # output = result.stdout.strip()
                    # total_entries += 1
                    data = ast.literal_eval(str(processed_data))
                    # Umwandlung von 'HasVulnerability' in 1 oder 0
                    has_vulnerability_value = 1 if (data.get('HasVulnerability') == 'Yes' or data.get('HasVulnerability')  == 'True' or data.get('HasVulnerability')  == True or data.get('HasVulnerability')  == 'true') else 0
                    
                    # Setze VulnerabilityDetect basierend auf dem Output-Wert
                    #vulnerability_match = 1 if float(output) >= 0.75 else 0

                    #print(f"Erkennungsrate von {cve_id} (unter Berücksichtigung von exakten und ähnlichen Übereinstimmungen): {output}")
                    print(f"Vorhandene Schwachstelle: {'Yes' if has_vulnerability_value else 'No'}")
                    print(f"Eintrag für {software}, Version {version} wurde zur CSV hinzugefügt.")
                    print("*" * 80)
                    
                   # Konvertiere has_vulnerability_value und vulnerability_detect explizit in Strings
                    has_vulnerability_value_str = str(has_vulnerability_value)
                    #vulnerability_match_str = str(vulnerability_match)

                    # Stelle sicher, dass auch software und version als Strings behandelt werden.
                    # Dies ist eine Vorsichtsmaßnahme, falls diese Variablen nicht bereits als Strings initialisiert wurden.
                    software_str = str(software)
                    version_str = str(version)

                    # Schreibe nun alle Werte als Strings in die CSV-Datei
                    writer.writerow([software_str, version_str, has_vulnerability_value_str, data.get('VulnerabilityTypes'), data.get('CVE-IDs')])

                    # Ausgabe in der Konsole (optional)
                    

# Hinweis: Das Schreiben in die CSV-Datei erfolgt innerhalb eines `with`-Blocks,
# um sicherzustellen, dass die Datei ordnungsgemäß geschlossen wird.


if __name__ == "__main__":
    json_file_path = 'positiveList_145 copy.json'
    csv_file_path = 'allitems.csv'
    main(json_file_path, csv_file_path)
