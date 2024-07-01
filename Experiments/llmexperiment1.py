import os
from callLLamaIndex import init, process_dataLLamaIndex, processGPT4, processLLama70B, processAzureOpenAIGPT4,processMistralLarge
import json

import json
import subprocess
import ast
import csv

json_file_path = 'positiveList_479.json'
csv_file_path = 'allitems.csv'

class LanguageModelSelector:
    def run(self):
        print("Please select the language model you want to use by entering the corresponding number:")        
        print("2: LLaMA Index GPT-4 Turbo")
        print("4: GPT-4 Turbo")
        print("70: Llama 2 70B")
        print("22: Azure AI Search GPT-4 Turbo")
        print("5: Mistral Large")       
        
        llm = input("Enter your choice: ")        
        try:
            llm = int(llm)
            if llm in [1, 2, 3, 4,5, 70, 22]:
                self.check_resource_exists(llm)           
            else:
                print("Invalid choice. Please enter a number from the list.")
        except ValueError:
            print("Invalid input. Please enter a number.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
    
    def RunProcess(self, model, index, resultfile):       
        with open(json_file_path, 'r') as file:
            data = json.load(file)

        with open(resultfile, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file, delimiter=';')
            writer.writerow(['Software', 'Version', 'LLMSaysHasVulnerability', 'LLMSaysHasThisVulnerability', 'LLMsaysThisCVEId', 'LLMsaysThisCWEId', 'LLMsaysThisScore'])
            count = 0
            for row in data:
                count+=1
                print(count)
                software = row['Software']
                version = row['Version']                
                
                processed_data = None
                if model == 2:
                    processed_data = process_dataLLamaIndex(software, version, index)
                elif model == 4:
                    processed_data = processGPT4(software, version)
                elif model == 70:
                    processed_data = processLLama70B(software, version)
                elif model == 5:
                    processed_data = processMistralLarge(software, version)
                elif model == 22:
                    processed_data = processAzureOpenAIGPT4(software, version)
                
                if processed_data is not None:                
                    if not isinstance(processed_data, list):
                        processed_data = [processed_data]                    
                    for processed_entry in processed_data:
                        data = ast.literal_eval(str(processed_entry))                    
                        has_vulnerability_value = 1 if (data.get('HasVulnerability') in ['Yes', 'True', 'true', True]) else 0
                        
                        print(f"Vorhandene Schwachstelle: {'Yes' if has_vulnerability_value else 'No'}")
                        print(f"Eintrag für {software}, Version {version} wurde zur CSV hinzugefügt.")
                        print("*" * 80)
                        
                        writer.writerow([
                            software, 
                            version, 
                            data.get('HasVulnerability'), 
                            data.get('VulnerabilityTypes'), 
                            data.get('CVE-IDs'),
                            data.get('CWE-IDs'),
                            data.get('Score')
                        ])

    def check_resource_exists(self, model_choice):
        result_files = {           
            2: "results_llama_index_gpt4_turbo.csv",          
            4: "results_gpt4.csv",
            5: "results_mistral.csv",
            70: "results_llama_70b.csv",
            22: "results_aisearchgpt4.csv"
        }
        filename = result_files.get(model_choice)
        
        if os.path.exists(filename):
            print(f"A results list ({filename}) already exists for the chosen model.")
            user_choice = input("Do you want to create a new one (N)").upper()
            if user_choice == "N":
                self.create_new_results(model_choice)           
            else:
                print("Invalid choice.")
        else:
            self.create_new_results(model_choice)
     
        self.select_model_method(model_choice)
    
    def create_new_results(self, model_choice):
        print(f"Creating new results for model {model_choice}...")
    
    def create_confusion_matrix(self, model_choice):
        print(f"Creating confusion matrix for model {model_choice}...")

    def select_model_method(self, model_choice):      
        if model_choice == 2:
            self.UseLLamaIndexGPT4Turbo()       
        elif model_choice == 22:
            self.UseAzureAISearchGPT4()
        elif model_choice == 4:
            self.UseGPT4()
        elif model_choice == 5:
            self.UseMistral()
        elif model_choice == 70:
            self.UseLlama70b()    
  
    def UseGPT4(self):
        print("Using GPT-4...")
        self.RunProcess(4,"","results_gpt4.csv")
    def UseMistral(self):
        print("Using Mistral...")
        self.RunProcess(5,"","results_mistral.csv")    
    def UseGPT3(self):
        print("Using GPT-3...")    
    def UseLlama70b(self):
        print("Using Llama70B...")
        self.RunProcess(70,"","results_llama_70b.csv")    
    def UseAzureAISearchGPT4(self):
        self.RunProcess(22,"","results_aisearchgpt4.csv")    
    def UseLLamaIndexGPT4Turbo(self):
        index = init()
        self.RunProcess(2, index,"results_llama_index_gpt4_turbo.csv")

if __name__ == "__main__":
    selector = LanguageModelSelector()
    selector.run()
