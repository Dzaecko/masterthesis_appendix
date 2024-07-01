import os
from pathlib import Path

import os
import json
import logging
import sys

import time
import openai



from llama_index.embeddings.openai import OpenAIEmbedding
from llama_index.llms.openai import OpenAI

from llama_index.core.callbacks import CallbackManager
from llama_index.core import (
    VectorStoreIndex,
    SimpleDirectoryReader,
    StorageContext,
    load_index_from_storage,
)

# global default

#JSONReader   = download_loader("JSONReader")

def build_storage(data_dir, persist_dir):
    start_time = time.time()


    documents = SimpleDirectoryReader(data_dir).load_data()
    embed_model = OpenAIEmbedding(embed_batch_size=42, model="text-embedding-ada-002")  
    
    callback_manager = CallbackManager()
    index = VectorStoreIndex.from_documents(
    documents, embed_model=embed_model, callback_manager=callback_manager
    )
   
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
    logging.getLogger().addHandler(logging.StreamHandler(stream=sys.stdout))
    
    
    total_size = sum(os.path.getsize(os.path.join(data_dir, doc)) for doc in os.listdir(data_dir) if os.path.isfile(os.path.join(data_dir, doc)))
    number_of_documents = len(documents)
    average_size = total_size / number_of_documents if number_of_documents else 0
    
   
    if not os.path.exists(persist_dir):
        os.makedirs(persist_dir)
    
    
     
    index.storage_context.persist(persist_dir)
    end_time = time.time()
    build_time = end_time - start_time  # Berechnung der Bauzeit
        
    stats = {
            'total_documents': number_of_documents,
            'total_size': total_size,
            'average_document_size': average_size,
            'build_time_seconds': build_time  # Hinzufügen der Bauzeit zur Statistik
        }
    with open(os.path.join(persist_dir, "stats.json"), "w") as f:
        json.dump(stats, f, indent=4)

    return index

def read_from_storage(persist_dir):
    storage_context = StorageContext.from_defaults(persist_dir=persist_dir)
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
    logging.getLogger().addHandler(logging.StreamHandler(stream=sys.stdout))
    return load_index_from_storage(storage_context)

def adding_data_to_GPT():
    persist_dir = "storage"
    data_dir = "docs"
    if os.path.exists(persist_dir):
        index = read_from_storage(persist_dir)
    else:
        index = build_storage(data_dir, persist_dir)
    llm = OpenAI()
    #llm_predictor = LLMPredictor(llm=ChatOpenAI(temperature=0, model_name="gpt-4"))
    #service_context = ServiceContext.from_defaults(llm_predictor=llm_predictor)
    query = "Found the Common Vulnerabilities and Exposures (CVE) with the number 1999-0018"
    query_engine = index.as_query_engine(llm=llm)

    queries = [      
        'I use vBulletin. Are there any known vulnerabilities in',
        'Are there any known vulnerabilities in TeamPass 2.1.27.36. Tell me the CVE NUmber. If so, what are they? Please provide the JSON data for cve_number with the following format: {"Software": "<software_name>", "Version": "<version_number>", "VulnerabilityType": "<vulnerability_type>"}.',
        'Are there any known vulnerabilities in GitBook. If so, what are they? Tell me the CVE NUmber.',
        'Are there any known vulnerabilities in D-Link DIR-859 1.05 versions. If so, what are they? Tell me the CVE NUmber.',
        'I use PHP 7.2.1. Are there any known vulnerabilities in this version of PHP?. Also check the versions in the descriptions that are not directly named but where the description refers to the version. For example, version 4.3 is between 4.1 and 4.4',
       'I use PHP 7.2.8. Are there any known vulnerabilities in this version of PHP?. If so, what are they?',
        'Are know cves for ddos attacks on linux?.  If so, what are they? Tell me the CVE NUmber.',
    ]
    
    while True:
        user_input = input("Geben Sie eine Abfrage ein (oder 'exit' zum Beenden): ")
        if user_input.lower() == 'exit':
            break
        response = query_engine.query(user_input)
        print(response)

   

if __name__ == "__main__":
    adding_data_to_GPT()