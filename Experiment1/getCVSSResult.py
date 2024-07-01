import os
import json
import re
import csv
import random
import openai
from openai import OpenAI


cvss_description = """
As input, you have a description of a CVE-ID vulnerability. Please extract the metrics according to these guidelines: The CVSS Base Metrics provide a framework to rate the severity of security vulnerabilities based on different characteristics of an exploit. These metrics are divided into several categories, each representing a specific aspect of the vulnerability.

Attack Vector (AV):
- Network (N): The vulnerability can be exploited from anywhere across the network.
- Adjacent (A): The attack must be launched from the same local network or a logically adjacent network.
- Local (L): The attack requires local access or user interaction to succeed.
- Physical (P): The attacker needs physical access to or manipulation of the vulnerable component.

Attack Complexity (AC):
- Low (L): The attack does not require special conditions and has a high likelihood of success.
- High (H): The attack depends on conditions beyond the attacker's control, requiring more effort to exploit.

Privileges Required (PR):
- None (N): No privileges are required for exploitation.
- Low (L): The attacker requires privileges that provide basic user capabilities.
- High (H): Significant privileges are required for exploitation.

User Interaction (UI):
- None (N): No interaction from any user is required.
- Required (R): Requires the user to perform some action before exploitation.

Scope (S):
- Unchanged (U): The exploit affects only the vulnerable component.
- Changed (C): The exploit affects resources beyond the initial component.

Confidentiality (C):
- High (H): Total loss of confidentiality, leading to all resources being divulged.
- Low (L): Partial disclosure of restricted information; not all data is disclosed.
- None (N): No impact on confidentiality.

Integrity (I):
- High (H): Complete loss of integrity; the attacker can alter all protected files.
- Low (L): Partial modification is possible but does not impact the component critically.
- None (N): No impact on integrity.

Availability (A):
- High (H): Complete loss of availability; the component becomes completely inaccessible.
- Low (L): Performance degradation or interruptions occur but do not completely deny service.
- None (N): No impact on availability.

The output should be a CVSS vector, for example: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N
"""


def find_files(directory):
    """ Durchsucht den Ordner nach JSON-Dateien. """
    files = [f for f in os.listdir(directory) if f.endswith('.json')]
    return files

def api_call(prompt):

    client = OpenAI()
  
    #"ft:gpt-3.5-turbo-1106:personal:cvss:9Dhlyqqf"
    response = client.chat.completions.create(
    model="ft:gpt-3.5-turbo-1106:personal:cvss3000:9DySzoBm",
    messages=[
                {"role": "system", "content": "I am an useful assistant to calculate scores on this base:\n\n"
                                    },
                            {"role": "user", "content":  f"'{prompt}.  "
                                    "Bitte berechne den cvss vektor aus dem von mir bereitgestelltem Text.\n\n"
                                    "Ich möchte nur den cvss vektor als Rückgabe haben"
                                      "Beispiel:  CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"
                 },           
            ]
            )

        # Verwenden von Regular Expressions, um das JSON-Objekt zu finden
    response_text = response.choices[0].message.content
    # Versuche, eine Gleitkommazahl aus dem Text zu extrahieren
    cvss_match = re.search(r'CVSS:\d\.\d(/[\w\-]+:[\w\-]+)+', response_text)
    if cvss_match:
        cvss_score = cvss_match.group()        
        print("CVSS Score:", cvss_score)
        return cvss_score
    else:
        print("Kein numerischer Wert gefunden.")
        return None
    
def extract_score_components(cvss_score):
    """ Extrahiert die Komponenten des CVSS-Scores aus dem String, filtert nach bekannten Metriken. """
    components = {}
    known_metrics = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}  # Definiere die bekannten Metriken
    parts = cvss_score.split('/')
    for part in parts[1:]:  # Das erste Element überspringen, da es "CVSS:3.1" ist
        key, value = part.split(':')
        if key in known_metrics:  # Filtere nach bekannten Metriken
            components[key] = value
    return components

def compare_scores(true_score, predicted_score):
    """ Vergleicht die beiden Scores und gibt die Übereinstimmungen zurück """
    true_components = extract_score_components(true_score)
    predicted_components = extract_score_components(predicted_score)
    results = {}
    for key in true_components:
        results[key] = true_components[key] == predicted_components.get(key, None)
    return results
def calculate_individual_matches(results):
    """ Berechnet die Übereinstimmung für jede Metrik über alle Ergebnisse """
    if not results:
        return {}
    match_counts = {key: 0 for key in results[0].keys()}
    total_counts = {key: 0 for key in results[0].keys()}

    for result in results:
        for key, matched in result.items():
            if matched:
                match_counts[key] += 1
            total_counts[key] += 1

    match_percentages = {key: (match_counts[key] / total_counts[key]) * 100 for key in match_counts}
    return match_percentages

def calculate_match_percentage(results):
    """ Berechnet die prozentuale Übereinstimmung für jede Komponente und gibt diese zurück """
    total_components = len(results)
    correct_matches = sum(val == True for val in results.values())
    match_percentage = (correct_matches / total_components) * 100 if total_components > 0 else 0
    return match_percentage

def process_files(directory):
    """ Verarbeitet jede Datei und speichert zufällig ausgewählte Dateien, die die Kriterien erfüllen. """
    eligible_files = []
    for filename in find_files(directory):
        with open(os.path.join(directory, filename), 'r', encoding='utf-8') as file:
            try:
                data = json.load(file)
                if 'metrics' in data.get('containers', {}).get('cna', {}) and 'cvssV3_1' in data['containers']['cna']['metrics'][0]:
                    if 'baseScore' in data['containers']['cna']['metrics'][0]['cvssV3_1']:
                        eligible_files.append(filename)
            except json.JSONDecodeError as e:
                print(f"Fehler beim Parsen der Datei {filename}: {e}")
                continue

    selected_files = random.sample(eligible_files, min(100, len(eligible_files)))
    results = []
    total_match_percentage = 0
    all_comparisons = []
    for filename in selected_files:
        with open(os.path.join(directory, filename), 'r', encoding='utf-8') as file:
            try:
                data = json.load(file)
                value = data['containers']['cna']['descriptions'][0]['value']
                score_data = api_call(value)
                if score_data in score_data:
                    try:
                        cve_id = data['cveMetadata']['cveId']
                        vectorString = data['containers']['cna']['metrics'][0]['cvssV3_1']['vectorString']
                        llm_score = score_data
                        comparison_results = compare_scores(vectorString, llm_score)
                        all_comparisons.append(comparison_results)
                    except ValueError as ve:
                        print(f"Fehler bei der Konvertierung von Werten in der Datei {filename}: {ve}")
            except json.JSONDecodeError as e:
                print(f"Fehler beim Parsen der Datei {filename}: {e}")
            except Exception as ex:
                print(f"Unbekannter Fehler beim Verarbeiten der Datei {filename}: {ex}")
    individual_matches = calculate_individual_matches(all_comparisons)
    print("Übereinstimmungsrate für jede Metrik:")
    for metric, match_rate in individual_matches.items():
        print(f"{metric}: {match_rate:.2f}%")
    save_results_to_csv(individual_matches)


def save_results_to_csv(match_percentages, filename="match_percentages.csv"):
    """ Speichert die Übereinstimmungsrate für jede Metrik in einer CSV-Datei """
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Metric', 'Match Percentage'])
        for key, value in match_percentages.items():
            writer.writerow([key, f"{value:.2f}%"])

def save_results(results, overall_match):
    """ Speichert die Ergebnisse und die Gesamtübereinstimmung in einer CSV-Datei. """
    with open('resultsgpt4.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['CVE-ID', 'CVSS v3.1 Score', 'LLM Score', 'Is Near', 'Match Percentage'])
        writer.writerows(results)
        writer.writerow(['Overall Match Percentage', '', '', '', overall_match])

# Verzeichnispfad ändern
directory = r'C:\Users\Dzaecko\Downloads\cvelistV5-main\cvelistV5-main\cvelist'
process_files(directory)
#save_results(results, overall_match)