#!/usr/bin/env python3
import pandas as pd
import json
import joblib

def extract_features_from_eve(file_path):
    relevant_features = []
    with open(file_path, 'r') as f:
        for line in f:  # Read each line individually
            try:
                log_entry = json.loads(line)  # Parse each line as a separate JSON object
                # Extract the fields you need from each log entry
                relevant_features.append({
                    'src_port': log_entry.get('src_port'),
                    'dest_port': log_entry.get('dest_port'),
                    'bytes_toserver': log_entry.get('flow', {}).get('bytes_toserver', 0),
                    'bytes_toclient': log_entry.get('flow', {}).get('bytes_toclient', 0),
                    'pkts_toserver': log_entry.get('flow', {}).get('pkts_toserver', 0),
                    'pkts_toclient': log_entry.get('flow', {}).get('pkts_toclient', 0),
                    'proto': log_entry.get('proto'),
                    'flow_duration': log_entry.get('flow', {}).get('age', 0),
                    # Add more fields as needed
                })
            except json.JSONDecodeError:
                continue  # Skip invalid lines

    return pd.DataFrame(relevant_features)


# Extract features from the eve.json file
eve_data = extract_features_from_eve('/path/to/eve.json')

# Apply the scaler and PCA from saved models
scaler = joblib.load('scaler.pkl')
pca = joblib.load('pca.pkl')

eve_data_scaled = scaler.transform(eve_data)  # Scaling the data
eve_data_pca = pca.transform(eve_data_scaled)  # Applying PCA

# Load your trained model
clf = joblib.load('isolation_forest_model.pkl')

# Predict anomalies
predictions = clf.predict(eve_data_pca)

# Anomaly prediction (1 for anomaly, 0 for benign)
alerts = ['Bad detected' if pred == -1 else 'Benign' for pred in predictions]

# Write alerts to a file
with open('/home/tomas/IA_ML_Suricata/alerts.txt', 'a') as f:
    for alert in alerts:
        f.write(f"{alert}\n")

