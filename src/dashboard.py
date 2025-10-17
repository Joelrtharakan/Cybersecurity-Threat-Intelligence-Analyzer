"""
dashboard.py
Professional interactive dashboard for Cybersecurity Threat Intelligence.
"""

from flask import Flask, render_template_string, jsonify
from pymongo import MongoClient
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd
from datetime import datetime
import numpy as np

app = Flask(__name__)

MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "cyber_intel"

# Custom color palette
COLORS = {
    'primary': '#2C3E50',
    'secondary': '#E74C3C',
    'accent': '#3498DB',
    'success': '#2ECC71',
    'warning': '#F1C40F',
    'background': '#ECF0F1'
}
client = MongoClient(MONGO_URI)
db = client[DB_NAME]

def get_threat_summary():
    """Get summary statistics of threats."""
    total_urls = db['urls'].count_documents({})
    counts = list(db['counts_by_type'].find())
    malicious = sum(d['value'] for d in counts if d['_id'] != 'benign')
    threat_scores = list(db['threat_scores'].find())
    avg_threat = np.mean([score['avg_threat_score'] for score in threat_scores]) if threat_scores else 0
    
    return {
        'total_urls': total_urls,
        'malicious_urls': malicious,
        'benign_urls': total_urls - malicious,
        'threat_percentage': round((malicious / total_urls * 100), 2) if total_urls > 0 else 0,
        'avg_threat_score': round(avg_threat, 2),
        'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

@app.route('/')
def index():
    # Fetch data
    counts = list(db['counts_by_type'].find())
    df_counts = pd.DataFrame(counts)

    domains = list(db['mal_domains'].find().sort('value', -1).limit(10))
    df_domains = pd.DataFrame(domains)

    scores = list(db['threat_scores'].find())
    df_scores = pd.DataFrame(scores)

    threat_summary = get_threat_summary()

    # Create subplots with improved layout
    fig = make_subplots(
        rows=3, cols=2,
        subplot_titles=(
            'URL Classification Distribution',
            'Top 10 Malicious Domains',
            'Average Threat Scores by Type',
            'Threat Score Distribution',
            'Threat Detection Timeline',
            'Security Summary'
        ),
        specs=[
            [{'type': 'pie'}, {'type': 'bar'}],
            [{'type': 'bar'}, {'type': 'histogram'}],
            [{'type': 'scatter'}, {'type': 'table'}]
        ],
        vertical_spacing=0.12,
        horizontal_spacing=0.1
    )

    # Pie chart for URL types
    fig.add_trace(
        go.Pie(
            labels=df_counts['_id'],
            values=df_counts['value'],
            hole=0.4,
            marker=dict(colors=[COLORS['success'] if x == 'benign' else COLORS['warning'] for x in df_counts['_id']]),
            textinfo='percent+label',
            hovertemplate="<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>"
        ),
        row=1, col=1
    )

    # Bar chart for malicious domains with improved styling
    fig.add_trace(
        go.Bar(
            x=df_domains['_id'],
            y=df_domains['value'],
            name='Detected Threats',
            marker_color=COLORS['secondary'],
            hovertemplate="<b>Domain: %{x}</b><br>Threats Detected: %{y}<extra></extra>"
        ),
        row=1, col=2
    )

    # Bar chart for threat scores with color gradient
    fig.add_trace(
        go.Bar(
            x=df_scores['_id'],
            y=df_scores['avg_threat_score'],
            name='Risk Level',
            marker=dict(
                color=df_scores['avg_threat_score'],
                colorscale='RdYlGn_r'
            ),
            hovertemplate="<b>Type: %{x}</b><br>Threat Score: %{y:.2f}<extra></extra>"
        ),
        row=2, col=1
    )

    # Add threat score distribution histogram
    all_scores = list(db['urls'].find({}, {'threat_score': 1}))
    scores_list = [doc.get('threat_score', 0) for doc in all_scores if 'threat_score' in doc]
    
    fig.add_trace(
        go.Histogram(
            x=scores_list,
            nbinsx=20,
            name='Score Distribution',
            marker_color=COLORS['accent'],
            hovertemplate="Score Range: %{x}<br>Count: %{y}<extra></extra>"
        ),
        row=2, col=2
    )

    # Add timeline of threats (last 7 days)
    timeline = list(db['urls'].find(
        {'timestamp': {'$exists': True}},
        {'timestamp': 1, 'type': 1}
    ).sort('timestamp', -1).limit(100))
    
    df_timeline = pd.DataFrame(timeline)
    if not df_timeline.empty and 'timestamp' in df_timeline:
        fig.add_trace(
            go.Scatter(
                x=df_timeline['timestamp'],
                y=[1] * len(df_timeline),
                mode='markers',
                marker=dict(
                    color=[COLORS['warning'] if t != 'benign' else COLORS['success'] for t in df_timeline['type']],
                    symbol='diamond',
                    size=10
                ),
                name='Threat Timeline',
                hovertemplate="<b>Detection Time</b>: %{x}<br>Type: %{text}<extra></extra>",
                text=df_timeline['type']
            ),
            row=3, col=1
        )

    # Enhanced summary table
    fig.add_trace(
        go.Table(
            header=dict(
                values=['<b>Security Metric</b>', '<b>Value</b>'],
                fill_color=COLORS['primary'],
                align=['left', 'center'],
                font=dict(color='white', size=12)
            ),
            cells=dict(
                values=[
                    ['Total URLs Analyzed', 'Malicious URLs Detected', 'Detection Rate', 'Average Threat Score', 'Last Updated'],
                    [
                        f"{threat_summary['total_urls']:,}",
                        f"{threat_summary['malicious_urls']:,}",
                        f"{threat_summary['threat_percentage']}%",
                        f"{threat_summary['avg_threat_score']:.2f}",
                        threat_summary['last_updated']
                    ]
                ],
                align=['left', 'center'],
                fill_color=[[COLORS['background']]],
                font=dict(color=[COLORS['primary']], size=11)
            )
        ),
        row=3, col=2
    )

    # Update layout with improved styling
    fig.update_layout(
        height=1200,
        template='plotly_white',
        title=dict(
            text="Cybersecurity Threat Intelligence Dashboard",
            x=0.5,
            font=dict(size=24, color=COLORS['primary'])
        ),
        showlegend=True,
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1
        ),
        paper_bgcolor=COLORS['background'],
        plot_bgcolor=COLORS['background']
    )

    # Update axes styling
    for i in fig['layout']['annotations']:
        i['font'] = dict(size=14, color=COLORS['primary'])

    graph_html = fig.to_html(full_html=False, config={'responsive': True})

    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Cybersecurity Threat Intelligence Dashboard</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet">
        <style>
            :root {
                --primary: """ + COLORS['primary'] + """;
                --secondary: """ + COLORS['secondary'] + """;
                --accent: """ + COLORS['accent'] + """;
                --background: """ + COLORS['background'] + """;
            }
            body {
                font-family: 'Inter', sans-serif;
                background-color: var(--background);
                margin: 0;
                padding: 20px;
                color: var(--primary);
            }
            .container {
                max-width: 1400px;
                margin: auto;
                background: white;
                padding: 30px;
                border-radius: 12px;
                box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            }
            .header {
                text-align: center;
                margin-bottom: 30px;
                padding-bottom: 20px;
                border-bottom: 2px solid var(--background);
            }
            h1 {
                margin: 0;
                color: var(--primary);
                font-size: 2.5em;
                font-weight: 600;
            }
            .subtitle {
                color: var(--secondary);
                font-size: 1.1em;
                margin-top: 10px;
            }
            .status-bar {
                display: flex;
                justify-content: space-between;
                margin: 20px 0;
                padding: 15px;
                background: var(--background);
                border-radius: 8px;
            }
            .status-item {
                text-align: center;
            }
            .status-label {
                font-size: 0.9em;
                color: var(--primary);
                margin-bottom: 5px;
            }
            .status-value {
                font-size: 1.2em;
                font-weight: 600;
                color: var(--secondary);
            }
            .chart-container {
                margin-top: 30px;
            }
            footer {
                text-align: center;
                margin-top: 30px;
                padding-top: 20px;
                border-top: 2px solid var(--background);
                color: var(--primary);
                font-size: 0.9em;
            }
            @media (max-width: 768px) {
                .status-bar {
                    flex-direction: column;
                    gap: 10px;
                }
                .container {
                    padding: 15px;
                }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔒 Cybersecurity Threat Intelligence Analyzer</h1>
                <p class="subtitle">Real-time Threat Detection and Analysis Dashboard</p>
            </div>
            
            <div class="status-bar">
                <div class="status-item">
                    <div class="status-label">Total URLs Analyzed</div>
                    <div class="status-value">{{ summary.total_urls }}</div>
                </div>
                <div class="status-item">
                    <div class="status-label">Threats Detected</div>
                    <div class="status-value">{{ summary.malicious_urls }}</div>
                </div>
                <div class="status-item">
                    <div class="status-label">Detection Rate</div>
                    <div class="status-value">{{ summary.threat_percentage }}%</div>
                </div>
                <div class="status-item">
                    <div class="status-label">Avg Threat Score</div>
                    <div class="status-value">{{ summary.avg_threat_score }}</div>
                </div>
            </div>

            <div class="chart-container">
                {{ graph_html | safe }}
            </div>

            <footer>
                <p>Last Updated: {{ summary.last_updated }} | Cybersecurity Threat Intelligence Platform</p>
            </footer>
        </div>
    </body>
    </html>
    """, graph_html=graph_html, summary=threat_summary)

def find_free_port(start_port=5001):
    """Find a free port starting from start_port."""
    import socket
    from contextlib import closing
    
    def is_port_free(port):
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            try:
                sock.bind(('0.0.0.0', port))
                return True
            except OSError:
                return False
    
    port = start_port
    while port < start_port + 100:  # Try up to 100 ports
        if is_port_free(port):
            return port
        port += 1
    raise OSError("No free ports found")

if __name__ == '__main__':
    try:
        # First, try to kill any existing process on port 5001
        import os
        os.system("lsof -ti:5001 | xargs kill -9 2>/dev/null")
        
        # Find a free port
        port = find_free_port()
        print(f"Starting dashboard on port {port}")
        app.run(debug=False, host='0.0.0.0', port=port, use_reloader=False)
    except Exception as e:
        print(f"Error starting server: {e}")