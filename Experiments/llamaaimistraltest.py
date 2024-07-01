import logging
import sys
from azure.core.credentials import AzureKeyCredential
from azure.search.documents import SearchClient
from azure.search.documents.indexes import SearchIndexClient

from llama_index.core import (
    SimpleDirectoryReader,
    StorageContext,
    VectorStoreIndex,
)
from llama_index.core.settings import Settings
from llama_index.core.vector_stores.types import VectorStoreQueryMode
from llama_index.llms.azure_openai import AzureOpenAI
from llama_index.embeddings.azure_openai import AzureOpenAIEmbedding
from llama_index.vector_stores.azureaisearch import AzureAISearchVectorStore
from llama_index.vector_stores.azureaisearch import (
    IndexManagement,
    MetadataIndexFieldType,
)


aoai_api_key = "a2x3794548"
aoai_endpoint = "https://cog-adgpt-dev-01.openai.azure.com/"
aoai_api_version = "2023-08-01-preview"

llm = AzureOpenAI(
    model="gpt-4",
    deployment_name="gpt-4",
    api_key=aoai_api_key,
    azure_endpoint=aoai_endpoint,
    api_version=aoai_api_version,
)

# You need to deploy your own embedding model as well as your own chat completion model
embed_model = AzureOpenAIEmbedding(
    model="text-embedding-ada-002",
    deployment_name="text-embedding-ada-002",
    api_key=aoai_api_key,
    azure_endpoint=aoai_endpoint,
    api_version=aoai_api_version,
)


search_service_api_key = "lTgs2jx4qhU6UpPAzSeCMt3fW"
search_service_endpoint = "https://searchdzaeck.search.windows.net"

credential = AzureKeyCredential(search_service_api_key)


# Index name to use
index_name = "vector-1713602691777-ragnew"



# Use search client to demonstration using existing index
search_client = SearchClient(
    endpoint=search_service_endpoint,
    index_name=index_name,
    credential=credential,
)
metadata_fields = {
    "title": "title",  
}
vector_store = AzureAISearchVectorStore(
    search_or_index_client=search_client,
    filterable_metadata_field_keys=metadata_fields,
    index_management=IndexManagement.VALIDATE_INDEX,    
    id_field_key="chunk_id",
    chunk_field_key="chunk",
    embedding_field_key="vector",
    embedding_dimensionality=1536,
    metadata_string_field_key="metadata",
    doc_id_field_key="doc_id",
)

storage_context = StorageContext.from_defaults(vector_store=vector_store)
index = VectorStoreIndex.from_documents(
    [],
    storage_context=storage_context,
)

query_engine = index.as_query_engine()
response = query_engine.query("What was a hard moment for the author?")

hybrid_retriever = index.as_retriever(
    vector_store_query_mode=VectorStoreQueryMode.SEMANTIC_HYBRID
)
hybrid_retriever.retrieve("What is inception about?")