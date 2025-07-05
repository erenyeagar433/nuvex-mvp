import json
import os
from typing import List, Dict
from sentence_transformers import SentenceTransformer, util

# Load model once
model = SentenceTransformer('all-MiniLM-L6-v2')

# Load memory base JSON
MEMORY_PATH = os.path.join(os.path.dirname(__file__), '../../dummy_data/memory_base.json')
with open(MEMORY_PATH, 'r') as f:
    memory_data = json.load(f)

# Preprocess and embed memory cases once
def preprocess_entry(entry):
    return f"{entry['description']} Source: {', '.join(entry['source_ips'])} | Dest: {', '.join(entry['destination_ips'])} | LogSource: {entry['log_source']} | Tags: {', '.join(entry.get('tags', []))}"

corpus_sentences = [preprocess_entry(entry) for entry in memory_data]
corpus_embeddings = model.encode(corpus_sentences, convert_to_tensor=True)


def find_similar_cases(current_offense: Dict, top_k: int = 3) -> List[Dict]:
    query_text = f"{current_offense['description']} Source: {', '.join(current_offense['source_ips'])} | Dest: {', '.join(current_offense['destination_ips'])} | LogSource: {', '.join(current_offense['log_sources'])}"
    query_embedding = model.encode(query_text, convert_to_tensor=True)

    # Compute cosine similarities
    scores = util.pytorch_cos_sim(query_embedding, corpus_embeddings)[0]
    top_results = scores.topk(k=top_k)

    similar_cases = []
    for score, idx in zip(top_results.values, top_results.indices):
        result = memory_data[idx]
        result["similarity_score"] = round(score.item(), 3)
        similar_cases.append(result)

    return similar_cases

