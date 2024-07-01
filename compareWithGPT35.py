
import os
import openai
import sys

cvellm = sys.argv[1]
cveorig = sys.argv[2]


endpoint = "https://agilecopilot1.openai.azure.com/"
api_key = "4e87e184a87346eda3fb015436357b99"
deployment = "thesismodel"

client = openai.AzureOpenAI(
    base_url=f"{endpoint}/openai/deployments/{deployment}",
    api_key=api_key,
    api_version="2023-08-01-preview",
)

completion = client.chat.completions.create(
    model=deployment,
    messages=[      
        {"role": "system", "content": "You are an AI assistant that helps people find information."},
        {"role": "user", "content": f"Please compare two security notifications regarding vulnerabilities in software. Each message contains information on the affected software and version, and the type of vulnerability. Indicate whether it is the same software and version (Yes/No), and whether it is the same vulnerability type (Yes/No). No further information, only the Yes/No messages. Example:\n\nSoftware=Yes\nVersion=Yes\nVulnerability type=No\n\nMessage 1:\n{cvellm}\nMessage 2:\n{cveorig}"}

    ],
 
    temperature=0.7,
    top_p=0.95,
    max_tokens=800,  
    frequency_penalty=0,
    presence_penalty=0,
    stop=None
)


output_text = completion.choices[0].message.content


print(output_text)