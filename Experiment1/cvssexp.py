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
api_key = "4e87e1XXXX436357b99"
gpt4dep = "userstory"
gpt3dep = "Bewerber"
import httpx
import time
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
import math
from llama_index.llms.openai import OpenAI
import csv
import urllib.request
import tiktoken
from llama_index.core import Settings
from llama_index.core import (
    VectorStoreIndex,
    SimpleDirectoryReader,
    StorageContext,
    load_index_from_storage,)
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

csv_file_path = 'output_cvss_data3finetunedall1.csv'


attack_vector_info = '''\
Attack Vector (AV)
- Network (N): The vulnerable component is bound to the network stack and the set of possible attackers extends beyond the other options listed below, up to and including the entire Internet. Such a vulnerability is often termed “remotely exploitable” and can be thought of as an attack being exploitable at the protocol level one or more network hops away (e.g., across one or more routers). An example of a network attack is an attacker causing a denial of service (DoS) by sending a specially crafted TCP...

- Adjacent (A): The vulnerable component is bound to the network stack, but the attack is limited at the protocol level to a logically adjacent topology. This can mean an attack must be launched from the same shared physical (e.g., Bluetooth or IEEE 802.11) or logical (e.g., local IP subnet) network, or from within a secure or otherwise limited administrative domain (e.g., MPLS, secure VPN to an administrative network zone). One example of an Adjacent attack would be an ARP (IPv4) or neighbor discovery (...

- Local (L): The vulnerable component is not bound to the network stack and the attacker’s path is via read/write/execute capabilities. Either:
  * The attacker exploits the vulnerability by accessing the target system locally (e.g., keyboard, console), or remotely (e.g., SSH); or
  * The attacker relies on User Interaction by another person to perform actions required to exploit the vulnerability (e.g., using social engineering techniques to trick a legitimate user into opening a malicious document).

- Physical (P): The attack requires the attacker to physically touch or manipulate the vulnerable component. Physical interaction may be brief (e.g., "evil maid" attack) or persistent. An example of such an attack is a cold boot attack in which an attacker gains access to disk encryption keys after physically accessing the target system. Other examples include peripheral attacks via FireWire/USB Direct Memory Access (DMA).
'''

attack_complexity = '''\
Attack Complexity (AC)
- Low (L): Specialized access conditions or extenuating circumstances do not exist. An attacker can expect repeatable success against the vulnerable component.
- High (H): Successful attack requires specialized access conditions or extenuating circumstances. Examples include:
  * The attacker must authenticate or spoof another user's identity.
  * The attack depends on user interaction (e.g., tricking someone into clicking a link).
'''

privileges_required = '''\
Privileges Required (PR)
- None (N): The attacker is unauthorized prior to attack, and requires no access to settings or files to exploit the vulnerability.
- Low (L): The attacker has limited access, but might require specific access, permissions, or privileges.
- High (H): The attacker has extensive permissions, such as administrator access.
'''
user_interaction = '''\
User Interaction (UI)
- None (N): No user interaction is required for the attacker to exploit the vulnerability.
- Required (R): Successful exploitation depends on an unwitting or intentional user action.
'''
scope = '''\
Scope (S)
- Unchanged (U): The exploited vulnerability does not cause changes in security impact across other components.
- Changed (C): The exploited vulnerability does cause changes in security impact across other components.
'''
confidentiality_impact = '''\
Confidentiality Impact (C)
- High (H): The attacker can obtain all sensitive information from the system.
- Low (L): The attacker can obtain partial, non-critical information.
- None (N): No confidentiality impact.
'''
integrity_impact = '''\
Integrity Impact (I)
- High (H): The attacker can modify data comprehensively or seriously corrupt it.
- Low (L): The attacker can modify data in a limited or non-critical manner.
- None (N): No impact on data integrity.
'''

availability_impact = '''\
Availability Impact (A)
- High (H): The attacker can severely disrupt system availability or cause a permanent denial of service.
- Low (L): The attacker can partially or temporarily disrupt system availability.
- None (N): No availability impact.
'''
promptold = "Extract the specific {metric_name} ({metric_shortname}) CVSS metric value from the provided CVE vulnerability description. Instead of returning the complete vector string, only return the value of the specified metric, for example formatted as '{metric_shortname}:L.' This is the CVE vulnerability description: {description}. Respond only with the value for the requested metric."

promptnew = "Extract the specific {metric_name} ({metric_shortname}) CVSS metric value from the provided CVE vulnerability description."
"Instead of returning the complete vector string, only return the value of the specified metric, for example formatted as '{metric_shortname}:L.' "
"This is the CVE vulnerability description: {description}. Respond only with the value for the requested metric."
"This is the definition of the cvss metric: {metric_info}"


with open(csv_file_path, mode='w', newline='', encoding='utf-8') as file:
    writer = csv.writer(file)
    writer.writerow(['CVE ID', 'Generated Vector String', 'Calculated Base Score', 'Calculated Severity', 'Original Base Score', 'Original Vector String', 'Original Severity', 'Input Tokens', 'Prompt Tokens'])

def read_from_storage(persist_dir):
    storage_context = StorageContext.from_defaults(persist_dir=persist_dir)
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
    logging.getLogger().addHandler(logging.StreamHandler(stream=sys.stdout))
    return load_index_from_storage(storage_context)


def processgpt3fintuned(description, baseSeverity):
    global total_time, call_count, unprocessed_count, inputTokens, inputTokensRAG, promptTokens, promptTokensRAG
    client = openai.OpenAI(               
                api_key="sk-cMlXXXXDp144VvVribOZ3Vp",                
            )
    completion = client.chat.completions.create(
                model="ft:gpt-3.5-turbo-1106:personal:vector3:9MOJEsHc",
                messages=[
                    {
                        "role": "user",
                        "content":  f"Generate a CVSS vector string from a CVE vulnerability description. Analyze the description and create the CVSS vector string based on this analysis. This is the CVE vulnerability description: {description}. Respond only with the CVSS vector string."
          },
                ],   
                temperature=0,
                top_p=1,
                max_tokens=1000,  
            )
    vector_string = extract_vector_string(completion.choices[0].message.content)
    base_score, severity = calculate_base_score(vector_string)
    print(f"Base Score: {base_score:.2f}, Severity: {severity}")
    inputTokensRAG += completion.usage.completion_tokens
    promptTokensRAG += completion.usage.prompt_tokens
    return vector_string, base_score, severity, inputTokensRAG, promptTokensRAG

def process_gpt4AISEarch(description, baseSeverity):
    global total_time, call_count, unprocessed_count, inputTokens, inputTokensRAG, promptTokens, promptTokensRAG
    endpoint = "https://agilecopilot1.openai.azure.com/"
    api_key = "4e87eXXXX015436357b99"
    deployment = "Bewerber"

    # endpoint = "https://cog-adgpt-dev-01.openai.azure.com/"
    # api_key = "a2e4e810bc5941c991dfd1f0d3794548"
    # deployment = "gpt-4"
    
    client = AzureOpenAI(
        base_url=f"{endpoint}/openai/deployments/{deployment}",
        api_key=api_key,
        api_version="2023-08-01-preview",
    )

    completion = client.chat.completions.create(
        model=deployment,
   
messages = [
    {
        "role": "user",
        "content": (
            f"Generate a CVSS vector string from a CVE vulnerability description. Analyze the description and create the CVSS vector string based on this analysis. This is the CVE vulnerability description: {description}. Respond only with the CVSS vector string."
          
        )
    },
],
        # extra_body={
        #     "dataSources": [
        #         {
        #             "type": "AzureCognitiveSearch",
        #             "parameters": {
        #                 "endpoint": "https://searchdzaeck.search.windows.net",
        #                 "key": "lTgs2jnUdSxfW",
        #                 "queryType": "vectorSemanticHybrid",
        #                 "semanticConfiguration" : "vector-1713602691777-ragnew-semantic-configuration",
        #                 "fieldsMapping": {},
        #                 "inScope": "false",                 
        #                 "strictness": 3,
        #                 "topNDocuments": 5,
        #                 "roleInformation": "You are an AI assistant that helps people find information"
        #                 "lessThanEqual and or prior and mathematical operators.",
        #                 "indexName": "vector-1713602691777-ragnew",
        #                 "embeddingDeploymentName": "text-embedding-ada-002"
        #             }
        #         }
        #     ]        
        # }, 
    
        temperature=0,
        top_p=1,
        max_tokens=800,  
    )
   
    vector_string = extract_vector_string(completion.choices[0].message.content)
    base_score, severity = calculate_base_score(vector_string)
    print(f"Base Score: {base_score:.2f}, Severity: {severity}")
    inputTokensRAG += completion.usage.completion_tokens
    promptTokensRAG += completion.usage.prompt_tokens
    return vector_string, base_score, severity, inputTokensRAG, promptTokensRAG
def roundup(x):
    """Round up to the nearest tenth as specified in CVSS v3.1"""
    return math.ceil(x * 10) / 10.0

def calculate_base_score(vector):
    metrics = {
        'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2},
        'AC': {'L': 0.77, 'H': 0.44},
        'PR': {'N': 0.85, 'L': 0.62, 'H': 0.27},  
        'UI': {'N': 0.85, 'R': 0.62},
        'S': {'U': 6.42, 'C': 7.52},
        'C': {'N': 0.0, 'L': 0.22, 'H': 0.56},
        'I': {'N': 0.0, 'L': 0.22, 'H': 0.56},
        'A': {'N': 0.0, 'L': 0.22, 'H': 0.56}
    }
    
    vector_elements = vector.replace("CVSS:3.1/", "").split('/')
    parsed_vector = {k.split(':')[0]: k.split(':')[1] for k in vector_elements}

    # Adjust the Privileges Required metric if the Scope is changed
    if parsed_vector['S'] == 'C':
        if parsed_vector['PR'] == 'L':
            metrics['PR']['L'] = 0.68
        if parsed_vector['PR'] == 'H':
            metrics['PR']['H'] = 0.50

    # Calculate Impact Sub-Score (ISS)
    iss = 1 - (1 - metrics['C'][parsed_vector['C']]) * (1 - metrics['I'][parsed_vector['I']]) * (1 - metrics['A'][parsed_vector['A']])
    
    # Calculate Impact
    if parsed_vector['S'] == 'U':
        impact = metrics['S']['U'] * iss
    else:
        impact = metrics['S']['C'] * (iss - 0.029) - 3.25 * (iss - 0.02)**15

    # Calculate Exploitability
    exploitability = 8.22 * metrics['AV'][parsed_vector['AV']] * metrics['AC'][parsed_vector['AC']] * metrics['PR'][parsed_vector['PR']] * metrics['UI'][parsed_vector['UI']]

    # Calculate Base Score
    if impact <= 0:
        base_score = 0
    else:
        if parsed_vector['S'] == 'U':
            base_score = roundup(min(impact + exploitability, 10))
        else:
            base_score = roundup(min(1.08 * (impact + exploitability), 10))

    # Determine severity rating
    if base_score == 0:
        severity = 'None'
    elif base_score <= 3.9:
        severity = 'Low'
    elif base_score <= 6.9:
        severity = 'Medium'
    elif base_score <= 8.9:
        severity = 'High'
    else:
        severity = 'Critical'

    return base_score, severity

def extract_random_files(base_folder, max_files=300):
    all_files = [os.path.join(dp, f) for dp, dn, filenames in os.walk(base_folder) for f in filenames if f.endswith('.json')]
    return random.sample(all_files, min(len(all_files), max_files))

  
def extract_vector_string(text):
    pattern = r'AV:[N,A,L,P]/AC:[L,H,M]/PR:[N,L,H]/UI:[N,R]/S:[U,C]/C:[N,L,H]/I:[N,L,H]/A:[N,L,H]'
    match = re.search(pattern, text)
    return match.group(0) if match else "No match found"



def extract_cvss_datarandomolder(base_folder,max_files=None):
    processed_files_count = 0
    for file_path in extract_random_files(r'C:\Users\Dzaecko\Downloads\cven\cvelistV5-main\cves', max_files=300):
             with open(file_path, 'r') as f:
                                with open(file_path, 'r') as file:
                                    data = json.load(file)
                                    # Navigate through the nested JSON structure
                                    for metric in data.get('containers', {}).get('cna', {}).get('metrics', []):
                                        cvss_data = metric.get('cvssV3_1', {})
                                        if 'baseScore' in cvss_data:  # Check if baseScore is available
                                            # Extract the description and vectorString if baseScore is present
                                            descriptions = data.get('containers', {}).get('cna', {}).get('descriptions', [])
                                            for desc in descriptions:
                                                print(f"CVE ID: {data.get('cveMetadata', {}).get('cveId', 'N/A')}")
                                                print(f"CVSS Base Score: {cvss_data.get('baseScore')}")
                                                print(f"CVSS Vector String: {cvss_data.get('vectorString', 'N/A')}")
                                                print(f"baseSeverity String: {cvss_data.get('baseSeverity', 'N/A')}")
                                                print(f"Description: {desc.get('value')}\n")
                                                vector_string, base_score, severity, inputTokens, promptTokensRAG = processgpt3fintuned(desc.get('value'), cvss_data.get('baseSeverity'))
                                                print(f"Vector String: {vector_string}")
                                                print(f"Calculated Base Score: {base_score}")
                                                print(f"Calculated Severity: {severity}\n")          
                                                processed_files_count += 1
                                                with open(csv_file_path, mode='a', newline='', encoding='utf-8') as file:
                                                    writer = csv.writer(file)
                                                    writer.writerow([data.get('cveMetadata', {}).get('cveId', 'N/A'), vector_string, base_score, severity, cvss_data.get('baseScore'), cvss_data.get('vectorString', 'N/A'), cvss_data.get('baseSeverity', 'N/A'), inputTokens, promptTokensRAG])
                           

def extract_cvss_data(base_folder,max_files=None):
    processed_files_count = 0
    # Loop through all subfolders in the base folder
    for subfolder in sorted(os.listdir(base_folder)):        
        #if subfolder.startswith("25") or subfolder.startswith("26") or subfolder.startswith("27") or \
        if   subfolder.startswith("28") or subfolder.startswith("29") or subfolder.startswith("30") or \
           subfolder.startswith("31") or subfolder.startswith("32") or subfolder.startswith("33") or \
           subfolder.startswith("34"):
            full_path = os.path.join(base_folder, subfolder)
            # Check if the path is indeed a directory
            if os.path.isdir(full_path):
                # Process each JSON file in the directory
                for filename in os.listdir(full_path):
                    if filename.endswith(".json"):  # Check if the file is a JSON file
                        if max_files is not None and processed_files_count <= max_files:
                            file_path = os.path.join(full_path, filename)
                            try:
                                with open(file_path, 'r') as file:
                                    data = json.load(file)
                                    # Navigate through the nested JSON structure
                                    for metric in data.get('containers', {}).get('cna', {}).get('metrics', []):
                                        cvss_data = metric.get('cvssV3_1', {})
                                        if 'baseScore' in cvss_data:  # Check if baseScore is available
                                            # Extract the description and vectorString if baseScore is present
                                            descriptions = data.get('containers', {}).get('cna', {}).get('descriptions', [])
                                            for desc in descriptions:   
                                                print(f"CVE ID: {data.get('cveMetadata', {}).get('cveId', 'N/A')}")
                                                print(f"CVSS Base Score: {cvss_data.get('baseScore')}")
                                                print(f"CVSS Vector String: {cvss_data.get('vectorString', 'N/A')}")
                                                print(f"baseSeverity String: {cvss_data.get('baseSeverity', 'N/A')}")
                                                print(f"Description: {desc.get('value')}\n")
                                                vector_string, base_score, severity, inputTokens, promptTokensRAG = processgpt3fintuned(desc.get('value'), cvss_data.get('baseSeverity'))
                                                 
                                                print(f"Vector String: {vector_string}")
                                                print(f"Calculated Base Score: {base_score}")
                                                print(f"Calculated Severity: {severity}\n")          
                                                processed_files_count += 1
                                                with open(csv_file_path, mode='a', newline='', encoding='utf-8') as file:
                                                    writer = csv.writer(file)
                                                    writer.writerow([data.get('cveMetadata', {}).get('cveId', 'N/A'), vector_string, base_score, severity, cvss_data.get('baseScore'), cvss_data.get('vectorString', 'N/A'), cvss_data.get('baseSeverity', 'N/A'), inputTokens, promptTokensRAG])
                            except Exception as e:
                                print(f"Error reading {filename}: {str(e)}")
                                

# Replace 'your_folder_path' with the actual path to the directory containing JSON files
extract_cvss_data(r'C:\Users\Dzaecko\Downloads\cven\cvelistV5-main\cves\2024', max_files=300)
#extract_cvss_datarandomolder(r'C:\Users\Dzaecko\Downloads\cven\cvelistV5-main\cves', max_files=100)
