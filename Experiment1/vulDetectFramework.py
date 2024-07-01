import subprocess
import os
import json
import re
import math
from openai import AzureOpenAI

os.environ["OPENAI_API_KEY"] = 'sk-cMlFzBxsDp144VvVribOZ3Vp'

# Azure OpenAI API-Konfiguration
endpoint = "https://cog-adgpt-dev-01.openai.azure.com/"
api_key = "a2e4e81x794548"
deployment = "gpt-4"
vullist = []
token_statistics = {
    'prompt_tokens': 0,
    'completion_tokens': 0
}
token_statisticsgpt3 = {
    'prompt_tokens': 0,
    'completion_tokens': 0
}
def scan_ips(ip_range):
    scan_results = []

    for ip in ip_range:
        try:
            print("Start nmap scan...")
            result = subprocess.run(
              ['nmap', '-sV', '-A', '-T4', '-p-', '--script', 
    'ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,smtp-commands,smtp-enum-users,smtp-ntlm-info,smtp-open-relay,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764,curl,http-title,http-headers,http-methods,http-enum', 
    ip
],

                capture_output=True, text=True
            )

            scan_results.append(result.stdout)
            print(result.stdout)
        except Exception as e:
            print(f"An error occurred while scanning {ip}: {e}")
            scan_results.append(f"Error scanning {ip}: {e}")

    return scan_results

def process_scan_results(scan_results):
    for scan_result in scan_results:
        json_result = process_gpt4AISEarch(scan_result)
        extract_and_process_json(json_result)

def process_software(name, version):
    global token_statistics
    global vullist
    client = AzureOpenAI(
        base_url=f"{endpoint}/openai/deployments/{deployment}/extensions",
        api_key=api_key,
        api_version="2023-08-01-preview",
    )

    completion = client.chat.completions.create(
        model=deployment,
        response_format={"type": "json_object"},
        messages=[
            {
                "role": "user",
                "content": (
                    f"""
Find possible vulnerabilities for this software. 
List the corresponding CVE entries in a JSON with description and also exploits if there are any. 
Do not give me any information about a software if the version is not directly affected by the vulnerability.

Name:  {name} Version: {version}

The output should be in this JSON format:
{{
  "name": "{name} {version}",
  "software": [
    {{
      "cve_entry": {{
        "number": "CVE-2023-0001",
        "description": "Description of the vulnerability 1"
      }}
    }},
    {{
      "cve_entry": {{
        "number": "CVE-2023-0002",
        "description": "Description of the vulnerability 2"
      }}
    }},
    {{
      "cve_entry": {{
        "number": "CVE-2023-0003",
        "description": "Description of the vulnerability 3"
      }}
    }}
  ]
}}
"""
                )
            }
        ],
        extra_body={
            "dataSources": [
                {
                    "type": "AzureCognitiveSearch",
                    "parameters": {
                        "endpoint": "https://searchdzaeck.search.windows.net",
                        "key": "lTgs2jnx4qhU6UpPAzSeCMt3fW",
                        "queryType": "vectorSemanticHybrid",
                        "semanticConfiguration": "vector-1713602691777-ragnew-semantic-configuration",
                        "fieldsMapping": {},
                        "inScope": "true",                 
                        "strictness": 3,
                        "topNDocuments": 5,
                        "roleInformation": "You are an AI assistant that helps people find information",                     
                        "indexName": "vector-1713602691777-ragnew",
                        "embeddingDeploymentName": "text-embedding-ada-002"
                    }
                }
            ]        
        },
        temperature=0,
        top_p=1,
        max_tokens=2000
    )

    token_statistics['prompt_tokens'] += completion.usage.prompt_tokens
    token_statistics['completion_tokens'] += completion.usage.completion_tokens
    result = completion.choices[0].message.content
    print(result)
    match = re.search(r'({.*})', result, re.DOTALL)
    if match:
        json_content = match.group(1)
        try:
            # Laden des JSON-Inhalts in ein Python-Objekt
            json_data = json.loads(json_content)

            # Vorbereiten der Daten für das Hinzufügen in die resultierende JSON-Datei
            name = json_data['name']
            version = name.split()[-1]  # Annahme, dass die Version immer am Ende des Namens steht

            # Durchlaufen der 'software'-Liste, um jedem 'cve_entry' den Namen und die Version hinzuzufügen
            output_data = []
            for software in json_data['software']:
                cve_entry = software['cve_entry']
                cve_entry['software_name'] = name
                cve_entry['software_version'] = version
                vector_string, base_score, severity = process_cvssScoreRanking(cve_entry['description'])
                cve_entry['cvss_vector'] = vector_string
                cve_entry['base_score'] = base_score
                cve_entry['severity'] = severity
                output_data.append(cve_entry)

            # Speichern des Ergebnisses in einer JSON-Datei
            with open('result.json', 'a', encoding='utf-8') as json_file:
                for entry in output_data:
                    json.dump(entry, json_file, indent=4, ensure_ascii=False)
                    json_file.write(',\n')  # Füge ein Komma hinzu, um Einträge zu trennen

        except json.JSONDecodeError as e:
            print(f"Fehler beim Laden des JSON-Inhalts: {e}")
    else:
        print("Kein JSON-Inhalt im Text gefunden.")

def process_cvssScoreRanking(description):
    global total_time, call_count, unprocessed_count, inputTokens, inputTokensRAG, promptTokens, promptTokensRAG
    endpoint = "https://agilecopilot1.openai.azure.com/"
    api_key = "4e87ex7b99"
    deployment = "Bewerber"

    # endpoint = "https://cog-adgpt-dev-01.openai.azure.com/"
    # api_key = "a2e4e810bc5941c991dfd1f0d3794548"
    # deployment = "gpt-4"
    
    client = AzureOpenAI(
        base_url=f"{endpoint}/openai/deployments/{deployment}/extensions",
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
     extra_body={
            "dataSources": [
                {
                    "type": "AzureCognitiveSearch",
                    "parameters": {
                        "endpoint": "https://searchdzaeck.search.windows.net",
                        "key": "lTgs2x6UpPAzSeCMt3fW",
                        "queryType": "vectorSemanticHybrid",
                        "semanticConfiguration": "vector-1713602691777-ragnew-semantic-configuration",
                        "fieldsMapping": {},
                        "inScope": "false",                 
                        "strictness": 3,
                        "topNDocuments": 5,
                        "roleInformation": "You are an AI assistant that helps people find information",                     
                        "indexName": "vector-1713602691777-ragnew",
                        "embeddingDeploymentName": "ada2"
                    }
                }
            ]        
        },
        temperature=0,
        top_p=1,
        max_tokens=2000,  
    )
   
    vector_string = extract_vector_string(completion.choices[0].message.content)
    if vector_string == "No match found":
        return vector_string, None, None
    base_score, severity = calculate_base_score(vector_string)
    print(f"Base Score: {base_score:.2f}, Severity: {severity}")
    token_statisticsgpt3['prompt_tokens'] += completion.usage.prompt_tokens
    token_statisticsgpt3['completion_tokens'] += completion.usage.completion_tokens
    return vector_string, base_score, severity
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

  
def extract_vector_string(text):
    pattern = r'AV:[N,A,L,P]/AC:[L,H,M]/PR:[N,L,H]/UI:[N,R]/S:[U,C]/C:[N,L,H]/I:[N,L,H]/A:[N,L,H]'
    match = re.search(pattern, text)
    return match.group(0) if match else "No match found"

def process_gpt4AISEarch(nmapscan):
    global token_statistics
    client = AzureOpenAI(
        base_url=f"{endpoint}/openai/deployments/{deployment}",
        api_key=api_key,
        api_version="2023-08-01-preview",
    )

    completion = client.chat.completions.create(
        model=deployment,
        response_format={"type": "json_object"},
        messages=[
            {
                "role": "user",
                "content": (
                    f"The context is an extended namp scan. ToDo:\n"
                    f" - Find  software, websites, webtechnologies, script language (like php, jquery, javascript, drupal, joomla), software libraries etc. and the corresponding version in the given context of the nmap scan.\n"
                    f" - If a version is not directly recognizable, take a closer look at the corresponding output realated to the software and try to deduce the version from it.\n"  
                     f" - Check the nmap scan several times for matches.\n"                                  
                    f"Your answer should be look like in this json example:\n"
                    f"f'{{'Results': ['\n"
                    f"f'{{'software': 'jquery.js', 'port': 8080, 'version': '2.3.4'}}, '\n"
                    f"f'{{'software': 'PHP', 'port': 22, 'version': '3.4'}}'\n"
                    f"f']}}'. This is the namp scan output:\n{nmapscan}"
                )
            }
        ],
        temperature=1,
        top_p=1,
        max_tokens=800,
    )
    token_statistics['prompt_tokens'] += completion.usage.prompt_tokens
    token_statistics['completion_tokens'] += completion.usage.completion_tokens
    result = completion.choices[0].message.content
    print(result)
    return result

def extract_and_process_json(json_text):

    json_match = json_text

    if json_match:
        try:
            software_data = json.loads(json_match)
            print("Extracted JSON Data:", software_data)  # Debug print
            process_software_data(software_data)
        except json.JSONDecodeError as e:
            print(f"JSON Decode Error: {e}")
    else:
        print("JSON not found in the provided text")

def process_software_data(data):
    if 'Results' in data:
        for software in data['Results']:
            name = software.get('software')
            version = software.get('version')
            process_software(name, version)
    elif 'nmap_scan' in data:
        for software in data['nmap_scan']:
            name = software.get('software')
            version = software.get('version')
            process_software(name, version)
    else:
        print("Key 'software' not found in the JSON data")  # Debug print

if __name__ == "__main__":
    ip_range = ["192.168.2.12"]
    results = scan_ips(ip_range)
    process_scan_results(results)
    with open('token_statisticsgpt3.json', 'w') as f:
        json.dump(token_statisticsgpt3, f, indent=4)
    with open('token_statistics.json', 'w') as f:
        json.dump(token_statistics, f, indent=4)
