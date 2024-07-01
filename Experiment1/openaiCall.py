import os
import json
import re
import random
import os
import shutil
import subprocess
from createLLamaIndex import adding_data_to_GPT
from callLLamaIndex import init, process_dataLLamaIndex, processGPT4, processLLama70B, processAzureOpenAIGPT4
import json
import subprocess
import os
from pathlib import Path

import os
import json

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


def processAzureOpenAIGPT4(software, version):
    global total_time, call_count, unprocessed_count
    
    # Startzeit des Aufrufs messen  
    endpoint = "https://agilecopilot1.openai.azure.com"
    api_key = "4e87e184x5436357b99"
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
                "content": (f'Are there any known vulnerabilities in {software} {version}? Please provide the JSON data for cve_number with the following format:'
                                      '{"Software": "<software_name>", "Version": "<version_number>", "HasVulnerability": "<has_vulnerability>", "VulnerabilityTypes": "<vulnerability_type>", "CVE-IDs": "<cve_id>", "PossibleAffectedVersions": "<poa_versions>", "CWE-IDs": "<cwe_id>", "Score": "<score>"}}. If there multiple CVD-IDs, CWE-IDs or VulnerabilityTypes, please separate them with a comma. Example: {"Software": "MYSQL", "Version": "5.5", "HasVulnerability": "1", "VulnerabilityTypes": "denial of service, xss", "CVE-IDs": "CVE-ID-2022, CVE-ID-6672, CVE-ID-32322", "PossibleAffectedVersions": "2, 6.7, 9", "CWE-IDs": "CWE-78, CWE-88", "Score": "5"}')
             
            },
        ],
        extra_body={
            "dataSources": [
                {
                    "type": "AzureCognitiveSearch",
                    "parameters": {
                        "endpoint": "https://searchdzaeck.search.windows.net",
                        "key": "I41ZLx5",
                        "queryType": "vectorSemanticHybrid",
                        "semanticConfiguration" : "vector-1712601683535-cve5500-semantic-configuration",
                        "fieldsMapping": {},
                        "inScope": "true",                 
                        "strictness": 3,
                        "topNDocuments": 5,
                        "roleInformation": "You are a helpful assistant.  ",
                        "indexName": "vector-1712601683535-cve5500",
                        "embeddingDeploymentName": "ada2"
                    }
                }
            ]        
        }, 
    
        temperature=0,
        top_p=1,
        max_tokens=800,  
    )
    json_objects = []

    json_matches = re.findall(r'\{.*?\}', completion.choices[0].message.content, re.DOTALL)    # Verwenden von Regular Expressions, um das JSON-Objekt zu finden
    for match in json_matches:
        try:            
            json_data = json.loads(match)
            print("Geparstes JSON:", json_data)
            json_objects.append(json_data)
        except json.JSONDecodeError:        
            print("Fehler beim Parsen:", match)

    # Überprüfen, ob JSON-Objekte gefunden und geparst wurden
    if json_objects:
        print(f"Gefundene JSON-Objekte: {json_objects}")                      
    else:
        print("Keine gültigen JSON-Objekte gefunden.")
        
     


def scan_files(directory):
    results = []
    # Durchsuche alle Dateien im angegebenen Verzeichnis
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        if os.path.isfile(file_path) and file_path.endswith('.json'):
            with open(file_path, 'r', encoding='utf-8') as file:
                try:
                    data = json.load(file)
                    if 'containers' in data and 'cna' in data['containers'] and 'metrics' in data['containers']['cna']:
                        cve_id = data['cveMetadata']['cveId'] if 'cveMetadata' in data and 'cveId' in data['cveMetadata'] else 'Unknown CVE-ID'
                        # Durchsuche alle Metriken, falls vorhanden
                        for metric in data['containers']['cna']['metrics']:
                            if 'cvssV3_1' in metric:
                                base_score = metric['cvssV3_1']['baseScore']
                                # Durchsuche alle betroffenen Produkte
                                if 'affected' in data['containers']['cna']:
                                    for product_entry in data['containers']['cna']['affected']:
                                        if 'versions' in product_entry and 'product' in product_entry:
                                            product_name = product_entry['product']
                                            for version_info in product_entry['versions']:
                                                # Prüfe, ob die Version Zahlen enthält und 'affected' Status hat
                                                version = version_info.get('version', '')
                                                if 'affected' == version_info.get('status', '') and re.search(r'\d', version):
                                                    results.append((product_name, version, base_score, cve_id))
                except json.JSONDecodeError:
                    print(f"Datei {filename} ist kein gültiges JSON-Format.")
                    
    return results

def get_random_entries(directory, num_samples=1000):
    # Erhalte alle passenden Einträge
    entries = scan_files(directory)
    # Wähle zufällige Einträge aus, wenn genug vorhanden sind
    if len(entries) >= num_samples:
        selected_entries = random.sample(entries, num_samples)
    else:
        selected_entries = entries
    return selected_entries

# Verzeichnis, das gescannt werden soll
directory = r'C:\Users\Dzaecko\Downloads\cvelistV5-main\cvelistV5-main\cvelist'

# Zufällige Einträge erhalten und ausdrucken
random_entries = get_random_entries(directory)
for entry in random_entries:
    print(f"Produkt: {entry[0]}, Version: {entry[1]}, Base Score: {entry[2]}, CVE-ID: {entry[3]}")
    processAzureOpenAIGPT4(entry[0], entry[1])



