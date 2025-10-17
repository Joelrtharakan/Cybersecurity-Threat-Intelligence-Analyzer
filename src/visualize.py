"""
visualize.py
Pulls MapReduce result collections and produces PNGs for your report/ppt.
Saves charts to report/images/
"""

import os
from pymongo import MongoClient
import pandas as pd
import matplotlib.pyplot as plt

MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "cyber_intel"
OUT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'report', 'images')
os.makedirs(OUT_DIR, exist_ok=True)

client = MongoClient(MONGO_URI)
db = client[DB_NAME]

def plot_top_types(n=10):
    cur = db['counts_by_type'].find().sort('value', -1).limit(n)
    rows = [(d['_id'], d['value']) for d in cur]
    if not rows:
        print("No data in counts_by_type. Run mapreduce_queries.py first.")
        return
    df = pd.DataFrame(rows, columns=['type','count'])
    df.set_index('type', inplace=True)
    ax = df.plot(kind='bar', legend=False, figsize=(10,6))
    ax.set_title('Top URL Types')
    ax.set_ylabel('Count')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    out = os.path.join(OUT_DIR, 'top_types.png')
    plt.savefig(out)
    plt.close()
    print("Saved:", out)

def plot_top_mal_domains(n=15):
    cur = db['mal_domains'].find().sort('value', -1).limit(n)
    rows = [(d['_id'], d['value']) for d in cur]
    if not rows:
        print("No data in mal_domains. Run mapreduce_queries.py first.")
        return
    df = pd.DataFrame(rows, columns=['domain','count'])
    df.set_index('domain', inplace=True)
    ax = df.plot(kind='bar', legend=False, figsize=(12,6))
    ax.set_title('Top Malicious Domains')
    ax.set_ylabel('Count')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    out = os.path.join(OUT_DIR, 'top_malicious_domains.png')
    plt.savefig(out)
    plt.close()
    print("Saved:", out)

def plot_tld_distribution(n=20):
    cur = db['malicious_tld_counts'].find().sort('value', -1).limit(n)
    rows = [(d['_id'], d['value']) for d in cur]
    if not rows:
        print("No data in malicious_tld_counts. Run mapreduce_queries.py first.")
        return
    df = pd.DataFrame(rows, columns=['tld','count']).set_index('tld')
    ax = df.plot(kind='pie', y='count', figsize=(8,8), legend=False, autopct='%1.1f%%')
    ax.set_ylabel('')
    ax.set_title('Top TLDs for Malicious URLs')
    out = os.path.join(OUT_DIR, 'malicious_tld_pie.png')
    plt.savefig(out)
    plt.close()
    print("Saved:", out)

def main():
    plot_top_types()
    plot_top_mal_domains()
    plot_tld_distribution()

if __name__ == '__main__':
    main()