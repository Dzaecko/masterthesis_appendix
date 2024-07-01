import os
from pathlib import Path

import os
import json
import logging
import sys

import time




from llama_index.embeddings.openai import OpenAIEmbedding
from llama_index.llms.openai import OpenAI

from llama_index.core.callbacks import CallbackManager
from llama_index.core import (
    VectorStoreIndex,
    SimpleDirectoryReader,
    StorageContext,
    load_index_from_storage,
)

def build_storage(data_dir, persist_dir):
    start_time = time.time()

    start_time = time.perf_counter()
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
    
    end_time = time.time()
    build_time = end_time - start_time  # Berechnung der Bauzeit
    duration = time.perf_counter() - start_time
    print(duration)
    stats = {
        'total_documents': number_of_documents,
        'total_size': total_size,
        'average_document_size': average_size,
        'build_time_seconds': build_time  # Hinzufügen der Bauzeit zur Statistik
    }
    if not os.path.exists(persist_dir):
        os.makedirs(persist_dir)
    
    
     
    index.storage_context.persist(persist_dir)

    with open(os.path.join(persist_dir, "stats.json"), "w") as f:
        json.dump(stats, f, indent=4)

    return index

def read_from_storage(persist_dir):
    storage_context = StorageContext.from_defaults(persist_dir=persist_dir)
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
    logging.getLogger().addHandler(logging.StreamHandler(stream=sys.stdout))
    return load_index_from_storage(storage_context)

def adding_data_to_GPT():
    persist_dir = "./storage"
    data_dir = "./docs"
    if os.path.exists(persist_dir):
        index = read_from_storage(persist_dir)
        print("New LLamaIndex created")
    else:
        index = build_storage(data_dir, persist_dir)

    # while True:
    #     user_input = input("Geben Sie eine Abfrage ein (oder 'exit' zum Beenden): ")
    #     if user_input.lower() == 'exit':
    #         break
    #     response = query_engine.query(user_input)
    #     print(response)

   

if __name__ == "__main__":
    adding_data_to_GPT()