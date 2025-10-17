#!/usr/bin/env python3
"""
main.py
Runs the entire Cybersecurity Threat Intelligence Analyzer pipeline with one command.
"""

import os
import subprocess
import sys

def run_command(cmd, desc):
    print(f"Running: {desc}")
    full_cmd = f"./venv/bin/{cmd}"
    result = subprocess.run(full_cmd, shell=True, cwd=os.getcwd())
    if result.returncode != 0:
        print(f"Error in {desc}")
        sys.exit(1)
    print(f"Completed: {desc}\n")

def main():
    # Check if data exists
    if not os.path.exists('malicious_phish.csv'):
        print("Error: malicious_phish.csv not found. Download from Kaggle and place in root.")
        sys.exit(1)

    # Run pipeline
    run_command("python src/preprocess.py", "Preprocessing data")
    run_command("python src/ingest.py", "Ingesting into MongoDB")
    run_command("python src/mapreduce_queries.py", "Running aggregations")
    run_command("python src/visualize.py", "Generating visualizations")
    run_command("python src/ml_predict.py", "Training ML model")
    run_command("python src/anomaly_detect.py", "Detecting anomalies")

    print("Pipeline completed! Starting web dashboard...")
    import subprocess
    subprocess.Popen(["./venv/bin/python", "src/dashboard.py"])

if __name__ == '__main__':
    main()