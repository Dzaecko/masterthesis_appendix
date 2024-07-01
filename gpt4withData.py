import os
import openai
import re
import json
import sys 


# Azure AI Search setup
search_endpoint = "https://searchdzaeck.search.windows.net"; # Add your Azure AI Search endpoint here
search_key = "I41ZLKbe2xDfKxNnTlSAzSeBERxZ5"; # Add your Azure AI Search admin key here
search_index_name = "cveindexall"; # Add your Azure AI Search index name here

endpoint = "https://agilecopilot1.openai.azure.com/"
api_key = "4e87e184ax6357b99"
deployment = "userstory"

client = openai.AzureOpenAI(
    base_url=f"{endpoint}/openai/deployments/{deployment}",
    api_key=api_key,
    api_version="2023-08-01-preview",
)

if len(sys.argv) < 2:
    print("Verwendung: python script.py <CVE-Nummer>")
    sys.exit(1)

cve_number = sys.argv[1]
#cve_number = "CVE-2008-3580"

completion = client.chat.completions.create(
    model=deployment,
    messages=[
        {
            "role": "user",
            "content": (
    f'"content": "Please provide the JSON data for {cve_number} with the following format: '
    '{"Software": "<software_name>", "Version": "<version_number>", "VulnerabilityType": "<vulnerability_type>"}."'
)
        },
    ],
    extra_body={
        "dataSources": [
            {
                "type": "AzureCognitiveSearch",
                "parameters": {
                    "endpoint": "https://searchdzaeck.search.windows.net",
                    "key": "I41ZLKbe2xnTlSAzSeBERxZ5",
                    "queryType": "semantic",
                    "semanticConfiguration" : "default",
                    "fieldsMapping": {},
                    "inScope": "true",                 
                    "strictness": 3,
                    "topNDocuments": 5,
                    "roleInformation": "You are a helpful assistant. \nYou will give the result of my query in the following format:\n\nQuery:\nWhat is the CVE-2008-3536?\n\nResult:\n{  \n  \"Software\": \"HP OpenView Network Node Manager\",  \n  \"Version\": \"7.01, 7.51, 7.53\",  \n  \"VulnerabilityType\": \"Denial of Service\"  \n}  ",
                    "indexName": "cveindexall"
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

if json_match:
    json_str = json_match.group(0)
    json_data = json.loads(json_str)
    print(json_data)
else:
    print("Kein JSON gefunden.")
