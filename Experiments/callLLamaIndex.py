import json
import socket
import subprocess
import os
from pathlib import Path

import os
import json
from mistralai.client import MistralClient
from mistralai.models.chat_completion import ChatMessage
import os
import openai
from openai import OpenAI
import re
import json
import sys 
import urllib.request
endpoint = "https://agilecopilot1.openai.azure.com/"
api_key = "4e8XXX5436357b99"
gpt4dep = "userstory"
gpt3dep = "Bewerber"

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


total_time = 0
call_count = 0
unprocessed_count = 0


def processGPT4(software, version):
    global total_time, call_count, unprocessed_count
    
    # Startzeit des Aufrufs messen
    start_time = time.time()
    client = openai.AzureOpenAI(
            base_url=f"{endpoint}/openai/deployments/{gpt4dep}",
            api_key=api_key,
            api_version="2023-08-01-preview",
        )

    completion = client.chat.completions.create(
            model=gpt4dep,
            messages=[    {            
                    "role": "user",
                    "content": (f'Are there any known vulnerabilities in {software} {version}? Please provide the JSON data for cve_number with the following format:'
                                      '{"Software": "<software_name>", "Version": "<version_number>", "VulnerabilityType": "<vulnerability_type>", "HasVulnerability": "<has_vulnerability>", "VulnerabilityTypes": "<vulnerability_type>", "CVE-IDs": "<cve_id>", "PossibleAffectedVersions": "<poa_versions>"}.", "CWE-IDs": "<cwe_id>", "Score": "<score>"}}.')
           } ],   
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
        end_time = time.time()
        call_duration = end_time - start_time
        total_time += call_duration
        call_count += 1   

        if call_count > 0:
            average_time = total_time / call_count
            print(f"Gesamtlaufzeit: {total_time} Sekunden, Durchschnittliche Dauer eines Aufrufs: {average_time} Sekunden, Nicht verarbeitbare Datensätze: {unprocessed_count}")        
        return json_objects
    else:
        print("Keine gültigen JSON-Objekte gefunden.")
        end_time = time.time()
        call_duration = end_time - start_time
        total_time += call_duration
        call_count += 1   

        if call_count > 0:
            average_time = total_time / call_count
            print(f"Gesamtlaufzeit: {total_time} Sekunden, Durchschnittliche Dauer eines Aufrufs: {average_time} Sekunden, Nicht verarbeitbare Datensätze: {unprocessed_count}")        
        unprocessed_count += 1

def processAzureOpenAIGPT4(software, version):
    global total_time, call_count, unprocessed_count
    
    # Startzeit des Aufrufs messen
    start_time = time.time()
    endpoint = "https://agilecopilot1.openai.azure.com"
    api_key = "4e87e184XXXXXX5436357b99"
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
                        "key": "I41ZLKbe23XXXXXNnTlSAzSeBERxZ5",
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
    json_matches = re.findall(r'\{.*?\}', completion.choices[0].message.content, re.DOTALL) 
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
        end_time = time.time()
        call_duration = end_time - start_time
        total_time += call_duration
        call_count += 1   

        if call_count > 0:
            average_time = total_time / call_count
            print(f"Gesamtlaufzeit: {total_time} Sekunden, Durchschnittliche Dauer eines Aufrufs: {average_time} Sekunden, Nicht verarbeitbare Datensätze: {unprocessed_count}")        
        return json_objects
    else:
        print("Keine gültigen JSON-Objekte gefunden.")
        end_time = time.time()
        call_duration = end_time - start_time
        total_time += call_duration
        call_count += 1   

        if call_count > 0:
            average_time = total_time / call_count
            print(f"Gesamtlaufzeit: {total_time} Sekunden, Durchschnittliche Dauer eines Aufrufs: {average_time} Sekunden, Nicht verarbeitbare Datensätze: {unprocessed_count}")        
        unprocessed_count += 1


def processLLama70B(software, version):
        global total_time, call_count, unprocessed_count
        data =  {
        "messages": [
            {
            "role": "user",
                "content": (f'Are there any known vulnerabilities in {software} {version}? Please provide the JSON data for cve_number with the following format:'
                                      '{"Software": "<software_name>", "Version": "<version_number>", "VulnerabilityType": "<vulnerability_type>", "HasVulnerability": "<has_vulnerability>", "VulnerabilityTypes": "<vulnerability_type>", "CVE-IDs": "<cve_id>"}."}}.')
           },
        
        ],
        "temperature": 1,
        "max_tokens": 800
        }

        body = str.encode(json.dumps(data))

        url = 'https://Llama-2-70b-chat-svbxh-serverless.westus3.inference.ai.azure.com/v1/chat/completions'
        # Ersetzen Sie dies durch den primären/sekundären Schlüssel oder AMLToken für den Endpunkt
        api_key = 'njkWUo4K14ajVIjpRIR5ZsOqhwqy3f9a'
        if not api_key:
            raise Exception("A key should be provided to invoke the endpoint")

        headers = {'Content-Type':'application/json', 'Authorization':('Bearer '+ api_key)}
        start_time = time.time()
        req = urllib.request.Request(url, body, headers)

        try:
            response = urllib.request.urlopen(req)

            result = response.read().decode('utf-8')  # Decodieren der Antwort in einen String
            #result_json = json.loads(result)  # Parsen des Strings in ein JSON-Objekt
            
            json_objects = []

            result_json = json.loads(result)  # Parsen des Strings in ein JSON-Objekt
    
    # Zugreifen auf den 'content' Teil im 'assistant'
            content = result_json['choices'][0]['message']['content']
            json_matches = re.findall(r'\{.*?\}', content, re.DOTALL)    # Verwenden von Regular Expressions, um das JSON-Objekt zu finden
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
                end_time = time.time()
                call_duration = end_time - start_time
                total_time += call_duration
                call_count += 1   

                if call_count > 0:
                    average_time = total_time / call_count
                    print(f"Gesamtlaufzeit: {total_time} Sekunden, Durchschnittliche Dauer eines Aufrufs: {average_time} Sekunden, Nicht verarbeitbare Datensätze: {unprocessed_count}")        
                return json_objects
            else:
                print("Keine gültigen JSON-Objekte gefunden.")
                end_time = time.time()
                call_duration = end_time - start_time
                total_time += call_duration
                call_count += 1   

                if call_count > 0:
                    average_time = total_time / call_count
                    print(f"Gesamtlaufzeit: {total_time} Sekunden, Durchschnittliche Dauer eines Aufrufs: {average_time} Sekunden, Nicht verarbeitbare Datensätze: {unprocessed_count}")        
                unprocessed_count += 1
        except urllib.error.HTTPError as error:
            print("The request failed with status code: " + str(error.code))

            # Drucken Sie die Header aus, sie enthalten die Anforderungs-ID und den Zeitstempel, die für die Fehlerbehebung der Fehler nützlich sind
            print(error.info())
            print(error.read().decode("utf8", 'ignore'))

def processMistralLarge(software, version):
    global total_time, call_count, unprocessed_count

    api_key = 'IDRSaM7MNDUeKeqNeJtokcIDw8jZG1Ti'
    if not api_key:
        raise Exception("A key should be provided to invoke the endpoint")

    model = "mistral-large-latest"

    client = MistralClient(api_key=api_key)
    messages = [
        ChatMessage(role="user", content=f'Are there any known vulnerabilities in {software} {version}? Please provide the JSON data for cve_number with the following format:'
                                         '{"Software": "<software_name>", "Version": "<version_number>", "VulnerabilityType": "<vulnerability_type>", "HasVulnerability": "<has_vulnerability>", "VulnerabilityTypes": "<vulnerability_type>", "CVE-IDs": "<cve_id>", "PossibleAffectedVersions": "<poa_versions>"}, "CWE-IDs": "<cwe_id>", "Score": "<score>"}.')
    ]

    try:
        # Kein Streaming
        chat_response = client.chat(
            model=model,
            messages=messages,
        )

        result = chat_response.choices[0].message.content

        json_objects = []
        json_matches = re.findall(r'\{.*?\}', result, re.DOTALL)
        for match in json_matches:
            try:
                json_data = json.loads(match)
                print("Geparstes JSON:", json_data)
                json_objects.append(json_data)
            except json.JSONDecodeError:
                print("Fehler beim Parsen:", match)

        if json_objects:
            print(f"Gefundene JSON-Objekte: {json_objects}")

            call_count += 1
            if call_count > 0:
                average_time = total_time / call_count
                print(f"Gesamtlaufzeit: {total_time} Sekunden, Durchschnittliche Dauer eines Aufrufs: {average_time} Sekunden, Nicht verarbeitbare Datensätze: {unprocessed_count}")
            return json_objects
        else:
            print("Keine gültigen JSON-Objekte gefunden.")

            call_count += 1
            if call_count > 0:
                average_time = total_time / call_count
                print(f"Gesamtlaufzeit: {total_time} Sekunden, Durchschnittliche Dauer eines Aufrufs: {average_time} Sekunden, Nicht verarbeitbare Datensätze: {unprocessed_count}")
            unprocessed_count += 1

    except urllib.error.HTTPError as error:
        print("The request failed with status code: " + str(error.code))
        print(error.info())
        print(error.read().decode("utf8", 'ignore'))
    except urllib.error.URLError as e:
        if isinstance(e.reason, socket.timeout):
            print("Read timeout occurred")
            time.sleep(60)  # Warten Sie eine Minute
            return processMistralLarge(software, version)  # Versuch, den nächsten Datensatz zu verarbeiten
        else:
            raise e  # Andere URLErrors werden weitergeleitet
   

def init():    
    return read_from_storage()

def read_from_storage():
    persist_dir = "./storage"
    storage_context = StorageContext.from_defaults(persist_dir=persist_dir)
    return load_index_from_storage(storage_context)


def process_dataLLamaIndex(software, version, index):
    global total_time, call_count, unprocessed_count
    
    # Startzeit des Aufrufs messen
    start_time = time.time()
       # Angenommen, OpenAI und die as_query_engine-Methode sind definiert und importiert
    llm = OpenAI(model="gpt-4-0125-preview")
    query_engine = index.as_query_engine(llm=llm)
    response = query_engine.query(f'Are there any known vulnerabilities in {software} {version}? Please provide the JSON data for cve_number with the following format:'
                                      '{"Software": "<software_name>", "Version": "<version_number>", "VulnerabilityType": "<vulnerability_type>", "HasVulnerability": "<has_vulnerability>", "VulnerabilityTypes": "<vulnerability_type>", "CVE-IDs": "<cve_id>", "PossibleAffectedVersions": "<poa_versions>"}.", "CWE-IDs": "<cwe_id>", "Score": "<score>"}}.')

    # Überprüfen, ob die Antwort ein String ist
    if not isinstance(response, str):
        response = str(response)
    
    try:
        # Versuche, die Antwort direkt als JSON zu parsen
        json_data = json.loads(response)
        print("Direkt als JSON geparst:", json_data)
        return json_data
    except json.JSONDecodeError:
        # Wenn die Antwort nicht direkt als JSON geparst werden kann, suche mit regulärem Ausdruck
        json_match = re.search(r'\{.*?\}', response, re.DOTALL)
        if json_match:
            extracted_json = json_match.group()
            print("Gefundenes JSON:", extracted_json)
            return extracted_json
        else:
            print("Kein JSON gefunden.")
            unprocessed_count += 1

    end_time = time.time()
    call_duration = end_time - start_time
    total_time += call_duration
    call_count += 1


    if call_count > 0:
        average_time = total_time / call_count
        print(f"Gesamtlaufzeit: {total_time} Sekunden, Durchschnittliche Dauer eines Aufrufs: {average_time} Sekunden, Nicht verarbeitbare Datensätze: {unprocessed_count}")