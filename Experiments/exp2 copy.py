import os
import json
import random
import json
import subprocess
import socket
import os
from pathlib import Path

import os
import json
from packaging import version
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
api_key = "4e8XXXX357b99"
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
from llama_index.core.callbacks import CallbackManager, TokenCountingHandler
from llama_index.embeddings.openai import OpenAIEmbedding

from llama_index.llms.openai import OpenAI
import csv
import urllib.request
import tiktoken
from llama_index.core import Settings
from llama_index.core import (
    VectorStoreIndex,
    SimpleDirectoryReader,
    StorageContext,
    load_index_from_storage,
)
total_time = 0
call_count = 0
inputTokens = 0
promptTokens = 0
inputTokensRAG = 0
promptTokensRAG = 0
right_count = 0
index = None
false_count = 0
unprocessed_count = 0


def is_version_in_entry(version_to_check, entry):
    """Hilfsfunktion zum Durchsuchen aller Werte in einem Dictionary nach einer Version."""
    for value in entry.values():
        # Wenn der Wert eine Liste ist, prüfe jedes Element der Liste
        if isinstance(value, list):
            if any(str(version_to_check) in str(item) for item in value):  # Prüfe, ob die Version in irgendeinem Element der Liste als Substring vorkommt
                return True
        elif isinstance(value, dict):
            # Rekursive Überprüfung, wenn der Wert ein weiteres Dictionary ist
            if is_version_in_entry(version_to_check, value):
                return True
        # Prüfe, ob die gesuchte Version als Substring in den String-Werten vorhanden ist
        elif str(version_to_check) in str(value):  # Prüfe auf das Vorkommen als Substring
            return True
    return False

def check_cve_version(folder_path, cve_id, json_data):
    global total_time, call_count, unprocessed_count, inputTokens, inputTokensRAG, promptTokens, promptTokensRAG
    filename = f"{cve_id}.json"
    file_path = os.path.join(folder_path, filename)
    if not os.path.exists(file_path):
        print(f"Keine Datei gefunden für CVE-ID: {cve_id}")
        return
    with open(file_path, 'r', encoding='utf-8') as file:
        data = json.load(file)
    affected = data.get('containers', {}).get('cna', {}).get('descriptions', [])
    version_found = False
    for entry in affected:                           
            client = openai.OpenAI(               
                api_key="sk-cMlFzXXXXDp144VvVribOZ3Vp",                
            )
            completion = client.chat.completions.create(
                model="gpt-4-turbo-2024-04-09",
                messages=[
                    {
                        "role": "user",
                        "content": f"Check if this informations {json_data}, is within the scope of this description: {entry}. Response only in this format, no more additional informations. Give me information about if the version exactly : '{{'Version': '<version>', 'Software': '<software>', 'IsAffected': '<true/false>', 'Version Match':'<true/false>', 'Software Match':'<true/false>', 'Reason': '<reason>', 'VersionIsExactlyNamed':'<true/false>'}}'"
                    },
                ],   
                temperature=0,
                top_p=1,
                max_tokens=1000,  
            )

            # Verwenden von Regular Expressions, um das JSON-Objekt zu finden
            json_match = re.search(r'\{.*?\}', completion.choices[0].message.content, re.DOTALL)
            inputTokens += completion.usage.completion_tokens
            promptTokens += completion.usage.prompt_tokens
            if json_match:
                result_dict = eval(json_match.group(0))
                reason = result_dict['Reason']
                result_dict['CVE ID'] = cve_id
                if json_data.get("IsAffected") == result_dict['IsAffected']:
                    result_dict['LLMTrue'] = "True"
                    result_dict['LLMSaysIsAffected'] = json_data.get("IsAffected")
                else:
                    result_dict['LLMTrue'] = "False"
                    result_dict['LLMSaysIsAffected'] = json_data.get("IsAffected")

                print(f"{result_dict['CVE ID']} {result_dict['Software']} {result_dict['Version']}; Reason: {reason}: LLMisTRue: {result_dict['LLMTrue']}")
                return result_dict
               
def process_gpt4(product, versions, cve_id):
    global total_time, call_count, unprocessed_count, inputTokens, inputTokensRAG, promptTokens, promptTokensRAG
    endpoint = "https://cog-adgpt-dev-01.openai.azure.com/"
    api_key = "a2e4eXXXXX3794548"
    deployment = "gpt-4"

    client = AzureOpenAI(
        base_url=f"{endpoint}/openai/deployments/{deployment}",
        api_key=api_key,
        api_version="2023-09-01-preview",
    )

    completion = client.chat.completions.create(
        model=deployment,
       messages = [
    {
        "role": "user",
        "content": (
            f"Is this software {product} {versions} susceptible to vulnerabilities? Please provide only the JSON data for each CVE Number with the following format."
                '{"Software":"<software_name>", "Version":"<version_number>", "IsAffected":"<true/false>" , "CVE-ID": "<cve_id>"}'
                'No further information on the CVE from your side. Pay particular attention to features such as versions and check whether the version is really within the described range.' 
                'Check whether the name and version are within the scope of the CVE.'
                'If you dont find informations about the software and version give a single json response in that format: {"Software": "<software_name>", "Version": "<version_number>", "IsAffected": "No result returned", "CVE-ID": "None"}'
        )
    },
],
       
        temperature=0,
        top_p=1,
        max_tokens=800,  
    )

    json_objects = []
    result_dicts = []
    json_matches = re.findall(r'\{.*?\}', completion.choices[0].message.content, re.DOTALL)
    inputTokensRAG += completion.usage.completion_tokens
    promptTokensRAG += completion.usage.prompt_tokens
    for match in json_matches:
        try:
            json_data = json.loads(match)
            json_objects.append(json_data)
        except json.JSONDecodeError:
            print("Fehler beim Parsen:", match)
            continue

        # Überprüfen der CVE-IDs
        extracted_cve_ids = json_data.get("CVE-IDs", "").split(", ")
        for cve_id in extracted_cve_ids:
            filename = f"{cve_id}.json"
            file_path = os.path.join(folder_path, filename)    
            result_dicts.append(check_cve_version(folder_path, cve_id, json_data))      
        return result_dicts



def read_from_storage(persist_dir):
    storage_context = StorageContext.from_defaults(persist_dir=persist_dir)
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
    logging.getLogger().addHandler(logging.StreamHandler(stream=sys.stdout))
    return load_index_from_storage(storage_context)

def process_Mistral(product, versions, cve_id):
    global total_time, call_count, unprocessed_count, inputTokens, inputTokensRAG, promptTokens, promptTokensRAG, index

    api_key = 'IDRSaMXXXXXIDw8jZG1Ti'
    if not api_key:
        raise Exception("A key should be provided to invoke the endpoint")

    model = "mistral-large-latest"
    client = MistralClient(api_key=api_key)
    messages = [
        ChatMessage(role="user", content=f"Is this software Export any {product} {versions} susceptible to vulnerabilities? Please provide only the JSON data for each cve_number with the following format."
                '{"Software":"<software_name>", "Version":"<version_number>", "IsAffected":"<true/false>" , "CVE-ID": "<cve_id>"}'
                'No further information on the CVE from your side. Pay particular attention to features such as versions and check whether the version is really within the described range.' 
                'Check whether the name and version are within the scope of the CVE.'
                'If you dont find informations about the software and version give a single json response in that format: {"Software": "<software_name>", "Version": "<version_number>", "IsAffected": "No result returned", "CVE-ID": "None"}') ]
    
    chat_response = client.chat(
            model=model,
            messages=messages,
        )       
    json_objects = []
    result_dicts = []
    json_matches = re.findall(r'\{.*?\}', chat_response.choices[0].message.content, re.DOTALL)
    inputTokensRAG += chat_response.usage.completion_tokens
    promptTokensRAG += chat_response.usage.prompt_tokens
    for match in json_matches:
        try:
            json_data = json.loads(match)          
        except json.JSONDecodeError:
            print("Fehler beim Parsen:", match)
            continue
        if(json_data.get("CVE-ID") == "None"): #llm hat gar nichts erkannt
            result_dict = {'Version': versions, 'Software': product, 'CVE ID':'None','InScope': 'Unknown', 'IsAffected': 'No result returned', 'Version Match': 'False', 'Software Match': 'False', 'InScope':'False', 'Reason': 'No result returned', 'VersionIsExactlyNamed': 'False', 'LLMTrue': 'False', 'LLMSaysIsAffected': 'No result returned'}                                            
            result_dicts.append(result_dict)
            continue
        # Überprüfen der CVE-IDs
        extracted_cve_id = json_data.get("CVE-ID")
        #result = check_cve_version(folder_path, extracted_cve_id, json_data)
        result_dicts.append(check_cve_version(folder_path, extracted_cve_id, json_data))      
    return result_dicts
    
    


def process_LlamaIndex(product, versions, cve_id):
    global total_time, call_count, unprocessed_count, inputTokens, inputTokensRAG, promptTokens, promptTokensRAG, index

   
  
    token_counter = TokenCountingHandler(
    tokenizer=tiktoken.encoding_for_model("gpt-4-0125-preview").encode
)
   

    Settings.llm = OpenAI(model="gpt-4-0125-preview", temperature=0.2)
    Settings.callback_manager = CallbackManager([token_counter])
    
    persist_dir = "./storage"
    data_dir = "./docs"
   
    if index is None:        
        index = read_from_storage(persist_dir)
     
    
    print(token_counter.total_embedding_token_count)
    token_counter.reset_counts()
    llm = OpenAI(model="gpt-4-0125-preview")
    query_engine = index.as_query_engine(llm=llm)
    response = query_engine.query(f"Is this software Export any {product} {versions} susceptible to vulnerabilities? Please provide only the JSON data for each cve_number with the following format."
                '{"Software":"<software_name>", "Version":"<version_number>", "IsAffected":"<true/false>" , "CVE-ID": "<cve_id>"}'
                'No further information on the CVE from your side. Pay particular attention to features such as versions and check whether the version is really within the described range.' 
                'Check whether the name and version are within the scope of the CVE.'
                'If you dont find informations about the software and version give a single json response in that format: {"Software": "<software_name>", "Version": "<version_number>", "IsAffected": "No result returned", "CVE-ID": "None"}')

    # Überprüfen, ob die Antwort ein String ist

    if not isinstance(response, str):
        response = str(response)
    #token_counter.reset_counts()
       
    result_dicts = []
    json_matches = re.findall(r'\{.*?\}', response, re.DOTALL)
    inputTokensRAG += token_counter.total_embedding_token_count + token_counter.completion_llm_token_count
    promptTokensRAG += token_counter.prompt_llm_token_count    
    for match in json_matches:
        try:
            json_data = json.loads(match)          
        except json.JSONDecodeError:
            print("Fehler beim Parsen:", match)
            continue
        if(json_data.get("CVE-ID") == "None"): #llm hat gar nichts erkannt
            result_dict = {'Version': versions, 'Software': product, 'CVE ID':'None','InScope': 'Unknown', 'IsAffected': 'No result returned', 'Version Match': 'False', 'Software Match': 'False', 'InScope':'False', 'Reason': 'No result returned', 'VersionIsExactlyNamed': 'False', 'LLMTrue': 'False', 'LLMSaysIsAffected': 'No result returned'}                                            
            result_dicts.append(result_dict)
            continue
        # Überprüfen der CVE-IDs
        extracted_cve_id = json_data.get("CVE-ID")
        #result = check_cve_version(folder_path, extracted_cve_id, json_data)
        result_dicts.append(check_cve_version(folder_path, extracted_cve_id, json_data))      
    return result_dicts

def process_gpt4AISEarch(product, versions, cve_id):
    global total_time, call_count, unprocessed_count, inputTokens, inputTokensRAG, promptTokens, promptTokensRAG
    endpoint = "https://cog-adgpt-dev-01.openai.azure.com/"
    api_key = "a2e4e8XXXXd3794548"
    deployment = "gpt-4"
    
    client = AzureOpenAI(
        base_url=f"{endpoint}/openai/deployments/{deployment}/extensions",
        api_key=api_key,
        api_version="2023-08-01-preview",
    )

    completion = client.chat.completions.create(
        model=deployment,
    #    messages = [
    # {
    #     "role": "user",
    #     "content": (
    #         f"Are there any known vulnerabilities in {pr} 2.8? Please provide only the JSON data for cve_number with the following format. No more informnation to the cve from your side. Pay particular attention to features such as versions and check whether the version is really within the described range. Check if the name and the version is in scope of the cve. Give only a response from affected cves"
    #         '{"Software": "<software_name>", "Version": "<version_number>", "VulnerabilityTypes": "<vulnerability_type>", "CVE-ID": "<cve_id>", "vectorString": "<vectorString>", "InScope": "<true/false>", "Reason": "<reason>"}'
    #         "If there are multiple CVE-IDs add an extra json for each cve. "
    #         'Example: {"Software": "MYSQL", "Version": "5.5", "VulnerabilityTypes": "denial of service, xss", '
    #         '"CVE-ID": "CVE-ID-2022", "vectorString": "CVSS:3.1/AC:L/AV:A/A:H/C:H/I:H/PR:H/S:C/UI:N", "InScope": "true", "Reason": "Version is not equal in this cve"}'
    #         'If you dont have informations about the cve give a json response in that format: {"Software": "MYSQL", "Version": "5.5", "VulnerabilityTypes": "none", '
    #         '"CVE-ID": "none", "vectorString": "none", "InScope": "none", "Reason": "No Informations about the software"}'
    #         'If the versions do not match give a json response in that format: {"Software": "MYSQL", "Version": "5.5", "VulnerabilityTypes": "none", '
    #         '"CVE-ID": "none", "vectorString": "none", "InScope": "none", "Reason": "Vulnerabilitys found but not in this version"}'
    #     )
    # },
     messages = [
    {
        "role": "user",
        "content": (
            f"Has this software: MariaDB Server 10.2.1 known vulnerabilities? Please provide only the JSON data for each cve number with the following format."
                '{"Software":"<software_name>", "Version":"<version_number>", "CVE-ID": "<cve_id>", "WhyIsVersionInScope": "<whyIsVersionInScope>"}'               
        )
    },
],
        extra_body={
            "dataSources": [
                {
                    "type": "AzureCognitiveSearch",
                    "parameters": {
                        "endpoint": "https://searchdzaeck.search.windows.net",
                        "key": "lTgs2XXXXXAzSeCMt3fW",
                        "queryType": "vectorSemanticHybrid",
                        "semanticConfiguration" : "vector-1713602691777-ragnew-semantic-configuration",
                        "fieldsMapping": {},
                        "inScope": "true",                 
                        "strictness": 3,
                        "topNDocuments": 5,
                        "roleInformation": "You are an assistant to detect vulnerabilities in software components. Pay particular attention to whether a version is really affected according to the description",                     
                        "indexName": "vector-1713602691777-ragnew",
                        "embeddingDeploymentName": "text-embedding-ada-002"
                    }
                }
            ]        
        }, 
    
        temperature=0,
        top_p=1,
        max_tokens=1000,  
    )
   


    result_dicts = []
    json_matches = re.findall(r'\{.*?\}', completion.choices[0].message.content, re.DOTALL)
    inputTokensRAG += completion.usage.completion_tokens
    promptTokensRAG += completion.usage.prompt_tokens
    for match in json_matches:
        try:
            json_data = json.loads(match)          
        except json.JSONDecodeError:
            print("Fehler beim Parsen:", match)
            continue
        if(json_data.get("CVE-ID") == "None"): #llm hat gar nichts erkannt
            result_dict = {'Version': versions, 'Software': product, 'CVE ID':'None','IsAffected': 'Unknown', 'WhyIsVersionInScope': 'No result returned'}                                            
            result_dicts.append(result_dict)
            continue
        # Überprüfen der CVE-IDs
        extracted_cve_id = json_data.get("CVE-ID")
        #result = check_cve_version(folder_path, extracted_cve_id, json_data)
        #result_dicts.append(check_cve_version(folder_path, extracted_cve_id, json_data))  
        result_dicts.append(result_dict)  
    return result_dicts
    

def process_product_info(product, versions, cve_id, vector_score):
    global total_time, call_count, unprocessed_count, inputTokens, inputTokensRAG, promptTokens, promptTokensRAG
    print(f"Processing: Product: {product}, Versions: {versions}")
    return process_gpt4AISEarch(product, versions, cve_id)
    
    
          

    
 


def extract_product_versions(folder_path):
    global total_time, call_count, unprocessed_count, inputTokens, inputTokensRAG, promptTokens, promptTokensRAG, right_count, false_count
    
    # Startzeit des Aufrufs messen
    start_time = time.time()
    files = [f for f in os.listdir(folder_path) if f.endswith('.json')]
    random.shuffle(files)  # Mischen der gesamten Dateiliste
    results = []
    version_pattern = re.compile(r'^\d+\.\d+(\.\d+)?$')
    # Liste der spezifischen Softwarekomponenten
    software_list = [
        "nginx", "apache", "phpmyadmin", "mariadb", 
        "wordpress", "drupal", "samba", "postgresql", "postfix",
        "openssh", "BIND", "Exim", "Squid", "Dovecot", 
        "vsftpd", "proftpd", "openvpn", "gitea"
    ]
    count = 0
    while files and count < 100:
        
        filename = files.pop()  # Entferne die zuletzt ausgewählte Datei aus der Liste
        with open(os.path.join(folder_path, filename), 'r', encoding='utf-8') as file:
            data = json.load(file)
            cve_metadata = data.get('cveMetadata', {})
            cve_id = cve_metadata.get('cveId', 'No CVE ID found')            
            if cve_metadata.get('state') == 'PUBLISHED':
                containers = data.get('containers', {})
                
                for container in containers.values():
                    affected = container.get('affected', [])
                    metrics = container.get('metrics', [])

                    # Suche nach dem cvssV3.1 vectorString
                    vector_score = None
                 
                    
                    for entry in affected:
                            product = entry.get('product')
                            if product:
                                product_lower = product.lower()
                                valid_versions = [v['version'] for v in entry.get('versions', []) if v['status'] == 'affected' and v['version'] not in ['n/a', '*'] and version_pattern.match(v['version'])]
                                if len(valid_versions) == 1 and product_lower not in ['windows', 'microsoft'] and any(soft.lower() in product_lower for soft in software_list):
                                    count+=1
                                    result_dicts = process_product_info(product, valid_versions, cve_id, vector_score)
                                    if result_dicts == None:                                        
                                            call_count += 1
                                            result_dict = {'Version': valid_versions, 'Software': product, 'CVE ID':'None','IsAffected': 'Unknown', 'WhyIsVersionInScope': 'No result returned'}     
                                            results.append(result_dict)
                                            unprocessed_count += 1
                                            continue
                                    for result_dict in result_dicts:
                                        if result_dict == None:                                        
                                            result_dict = {'Version': valid_versions, 'Software': product, 'CVE ID':'None','IsAffected': 'Unknown', 'WhyIsVersionInScope': 'No result returned'}     
                                            results.append(result_dict)
                                            unprocessed_count += 1                                        
                                            continue
                                        else:
                                            results.append(result_dict)
                                            call_count += 1
                                            if result_dict['IsAffected'].lower() == 'true' or result_dict['IsAffected'].lower() == "yes":
                                                right_count += 1
                                            if result_dict['IsAffected'].lower() == 'false' or result_dict['IsAffected'].lower() == "no":
                                                false_count += 1
                                        # if result_dict['InScope'].lower() == 'true':
                                        #     results.append(result_dict)
                                        #     call_count += 1
                                        #     right_count += 1
                                        # if result_dict['InScope'].lower() == 'false':
                                        #     results.append(result_dict)
                                        #     call_count += 1
                                        #     false_count += 1                                                                   
                                    
    with open('resultsgpt4.csv', 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['Software', 'Version', 'CVE ID',  'Reason', 'Software Match', 'Version Match', 'IsAffected', 'VersionIsExactlyNamed', 'LLMTrue', 'LLMSaysIsAffected']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for result in results:
            writer.writerow({
                'Software': result['Software'],
                'Version': result['Version'],
                'CVE ID': result['CVE ID'],                              
                'Reason': result['Reason'],
                'Software Match': result['Software Match'],
                'Version Match': result['Version Match'],
                'IsAffected': result['IsAffected'],
                'VersionIsExactlyNamed': result['VersionIsExactlyNamed'],
                'LLMTrue': result['LLMTrue'],
                'LLMSaysIsAffected': result['LLMSaysIsAffected']
            })
    end_time = time.time()
    call_duration = end_time - start_time
    total_time += call_duration
    with open('statsgpt4.csv', 'w', newline='', encoding='utf-8') as csvfile:   
        fieldnames = [
   'Total Time', 'Call Count', 'Right', 'False', 
    'Input Tokens', 'Prompt Tokens', 'Input Tokens RAG', 'Prompt Tokens RAG', 'Cost Input Total', 'Cost Prompt Total', 'Cost Total', 'Unprocced'
]    
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerow({          
            'Total Time': f"{total_time:.2f} seconds",
            'Call Count': call_count,
            'Right': right_count,
            'False': false_count,
            'Input Tokens': inputTokens,
            'Prompt Tokens': promptTokens,
            'Input Tokens RAG': inputTokensRAG,
            'Prompt Tokens RAG': promptTokensRAG,
            'Cost Input Total': (inputTokens+inputTokensRAG)/1000*0.01,
            'Cost Prompt Total': (promptTokens+promptTokensRAG)/1000*0.03,
            'Cost Total': ((inputTokens+inputTokensRAG)/1000*0.01)+( (promptTokens+promptTokensRAG)/1000*0.03),
            'Unprocced': unprocessed_count
            })
    #random.shuffle(results)  # Durchmischen der Ergebnisse

if __name__ == '__main__':
    folder_path = r'C:\Users\Dzaecko\Downloads\cvelistV5-main\cvelistV5-main\cvelist'
    extract_product_versions(folder_path)
