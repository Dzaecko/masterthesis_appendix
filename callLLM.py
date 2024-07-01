
import os
import openai
from openai import OpenAI
import re
import json
import sys 
import urllib.request
endpoint = "https://agilecopilot1.openai.azure.com/"
api_key = "4e87e1x6357b99"
gpt4dep = "userstory"
gpt3dep = "Bewerber"




class TextGenerator:
    def __init__(self, prompt):
        self.prompt = prompt
    
    def UseGPT4(self):
        client = openai.AzureOpenAI(
            base_url=f"{endpoint}/openai/deployments/{gpt4dep}",
            api_key=api_key,
            api_version="2023-08-01-preview",
        )

        completion = client.chat.completions.create(
            model=gpt4dep,
            messages=[
                {
                    "role": "user",
                    "content": f"'{self.prompt}'"
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
    
    def UseLLamaIndexGPT4Turbo(self):
            client = openai.AzureOpenAI(
                base_url=f"{endpoint}/openai/deployments/{gpt3dep}",
                api_key=api_key,
                api_version="2023-08-01-preview",
            )

            completion = client.chat.completions.create(
                model=gpt3dep,
                messages=[
                    {
                        "role": "user",
                        "content": f"'{self.prompt}'"
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

    def UseGPT3(self):
         client = openai.AzureOpenAI(
            base_url=f"{endpoint}/openai/deployments/{gpt3dep}",
            api_key=api_key,
            api_version="2023-08-01-preview",
        )

         completion = client.chat.completions.create(
            model=gpt3dep,
            messages=[
                {
                    "role": "user",
                    "content": f"'{self.prompt}'"
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

    def UseOpenAIFinetuned(self):
         client = OpenAI()

         response = client.chat.completions.create(
            model="ft:gpt-3.5-turbo-1106:personal::8wAcu91u",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content":  f"'{self.prompt}'"},              
            ]
            )

        # Verwenden von Regular Expressions, um das JSON-Objekt zu finden
         json_match = re.search(r'\{.*?\}', response.choices[0].message.content, re.DOTALL)

         try:
                if json_match:
                    json_str = json_match.group(0)
                    json_data = json.loads(json_str)
                    print(json_data)
                    return json_data
                else:
                    print("Kein JSON gefunden.")   
         except:     
                 return {
            "HasVulnerability": None,
            "VulnerabilityTypes": None,
            "CVE-IDs": None,
            "PossibleAffectedVersions": None
                 }
    
    def UseLlama70b(self):
        data =  {
        "messages": [
            {
            "role": "user",
            "content":  f"'{self.prompt}'"
            },
        
        ],
        "temperature": 0,
        "max_tokens": 1000
        }

        body = str.encode(json.dumps(data))

        url = 'https://Llama-2-70b-chat-svbxh-serverless.westus3.inference.ai.azure.com/v1/chat/completions'
        # Ersetzen Sie dies durch den primären/sekundären Schlüssel oder AMLToken für den Endpunkt
        api_key = 'njkWxwqy3f9a'
        if not api_key:
            raise Exception("A key should be provided to invoke the endpoint")

        headers = {'Content-Type':'application/json', 'Authorization':('Bearer '+ api_key)}

        req = urllib.request.Request(url, body, headers)

        try:
            response = urllib.request.urlopen(req)

            result = response.read().decode('utf-8')  # Decodieren der Antwort in einen String
            result_json = json.loads(result)  # Parsen des Strings in ein JSON-Objekt
            
            # Zugreifen auf den 'content' Teil im 'assistant'
            content = result_json['choices'][0]['message']['content']
          
            json_match = re.search(r'\{.*?\}', content, re.DOTALL)
            try:
                if json_match:
                    json_str = json_match.group(0)
                    json_data = json.loads(json_str)
                    print(json_data)
                    return json_data
                else:
                    print("Kein JSON gefunden.")   
            except:     
                 return {
            "HasVulnerability": None,
            "VulnerabilityTypes": None,
            "CVE-IDs": None,
            "PossibleAffectedVersions": None
        }
        except urllib.error.HTTPError as error:
            print("The request failed with status code: " + str(error.code))

            # Drucken Sie die Header aus, sie enthalten die Anforderungs-ID und den Zeitstempel, die für die Fehlerbehebung der Fehler nützlich sind
            print(error.info())
            print(error.read().decode("utf8", 'ignore'))
    
    def generate_text(self, llm):
        if llm == 4:
            return self.UseGPT4()
        elif llm == 3:
            return self.UseGPT3()
        elif llm == 70:
            return self.UseLlama70b()
        elif llm == 1:
            return self.UseOpenAIFinetuned()
        elif llm == 2:
            return self.UseLLamaIndexGPT4Turbo()
        else:
            return "Unbekanntes LLM. Bitte wähle 3, 4 oder 70."

# Beispiel für die Verwendung der Klasse
prompt = "Beispieltext"
llm = 4  # Hier kannst du 3, 4 oder 70 eingeben

generator = TextGenerator(prompt)
result = generator.generate_text(llm)
print(result)
