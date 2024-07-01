

import urllib.request
import json
import os
import ssl
import sys

def allowSelfSignedHttps(allowed):
    # Bypass der Zertifikatsüberprüfung auf Clientseite
    if allowed and not os.environ.get('PYTHONHTTPSVERIFY', '') and getattr(ssl, '_create_unverified_context', None):
        ssl._create_default_https_context = ssl._create_unverified_context

allowSelfSignedHttps(True) # Diese Zeile ist erforderlich, wenn Sie ein selbstsigniertes Zertifikat in Ihrem Scoring-Service verwenden.

# Übergeben Sie die CVE-Nummer als Befehlszeilenargument
if len(sys.argv) < 2:
    print("Verwendung: python script.py <CVE-Nummer>")
    sys.exit(1)

cve_number = sys.argv[1]
#cve_number = "CVE-2008-3536"

# Erstellen Sie die Anfrage-Daten mit der übergebenen CVE-Nummer
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
api_key = 'njkWUo4K14xy3f9a'
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
    print(content)
except urllib.error.HTTPError as error:
    print("The request failed with status code: " + str(error.code))

    # Drucken Sie die Header aus, sie enthalten die Anforderungs-ID und den Zeitstempel, die für die Fehlerbehebung der Fehler nützlich sind
    print(error.info())
    print(error.read().decode("utf8", 'ignore'))
