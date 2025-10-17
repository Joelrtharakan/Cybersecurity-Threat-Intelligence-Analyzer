"""
visualize.py
Pulls MapReduce result collections and produces PNGs for your report/ppt.
Saves charts to report/images/
"""

import os
from pymongo import MongoClient
import pandas as pd
import matplotlib.pyplot as plt
import plotly.express as px

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

def plot_threat_scores():
    cur = db['threat_scores'].find()
    rows = [(d['_id'], d['avg_threat_score']) for d in cur]
    if not rows:
        print("No data in threat_scores.")
        return
    df = pd.DataFrame(rows, columns=['type','avg_score'])
    df.set_index('type', inplace=True)
    ax = df.plot(kind='bar', legend=False, figsize=(10,6))
    ax.set_title('Average Threat Scores by Type')
    ax.set_ylabel('Score')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    out = os.path.join(OUT_DIR, 'threat_scores.png')
    plt.savefig(out)
    plt.close()
    print("Saved:", out)

def plot_country_map():
    # Get country data
    cur = db['country_counts'].find()
    rows = [(d['_id'], d['count']) for d in cur if d['_id'] not in ['Unknown', None]]
    if not rows:
        print("No data in country_counts.")
        return
    
    df = pd.DataFrame(rows, columns=['country', 'count'])
    
    # Create a more detailed choropleth map
    fig = px.choropleth(
        df,
        locations='country',
        locationmode='ISO-3',
        color='count',
        color_continuous_scale='Viridis',
        range_color=[df['count'].min(), df['count'].max()],
        title='Global Distribution of Malicious URLs',
        labels={'count': 'Number of Malicious URLs'},
    )
    
    # Enhance the map layout
    fig.update_layout(
        title={
            'text': 'Global Distribution of Malicious URLs',
            'y':0.9,
            'x':0.5,
            'xanchor': 'center',
            'yanchor': 'top',
            'font': {'size': 24}
        },
        geo=dict(
            showframe=True,
            showcoastlines=True,
            projection_type='equirectangular',
            showocean=True,
            oceancolor='lightblue',
            showland=True,
            landcolor='lightgrey',
            showcountries=True,
            countrycolor='white',
            countrywidth=0.5,
        ),
        width=1200,
        height=800,
        margin={"r":0,"t":30,"l":0,"b":0}
    )
    
    # Add hover template
    fig.update_traces(
        hovertemplate='<b>Country:</b> %{location}<br>' +
                      '<b>Malicious URLs:</b> %{z:,.0f}<br><extra></extra>'
    )
    
    out = os.path.join(OUT_DIR, 'country_map.html')
    fig.write_html(out, include_plotlyjs=True, full_html=True)
    print("Saved:", out)

def main():
    plot_top_types()
    plot_top_mal_domains()
    plot_tld_distribution()
    plot_threat_scores()
    plot_country_map()

if __name__ == '__main__':
    main()