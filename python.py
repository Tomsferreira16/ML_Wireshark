#!/usr/bin/env python3
import json
import pandas as pd
import joblib
from datetime import datetime

# Function to load and parse eve.json and extract relevant features
def extract_features_from_eve(file_path):
    features_list = []

    with open(file_path, 'r') as file:
        for line in file:
            data = json.loads(line.strip())

            # Initialize the features dictionary with missing fields set to 0
            features = {
                'Flow Duration': 0,
                'Total Fwd Packets': 0,
                'Total Backward Packets': 0,
                'Total Length of Fwd Packets': 0,
                'Total Length of Bwd Packets': 0,
                'ACK Flag Count': 0,  # Placeholder for missing features
                'Active Max': 0,      # Placeholder for missing features
                'Active Mean': 0,     # Placeholder for missing features
                'Active Min': 0,      # Placeholder for missing features
                'Active Std': 0,      # Placeholder for missing features
            }

            if 'flow' in data:
                flow = data['flow']

                # Calculate flow duration
                start_time = datetime.strptime(flow['start'], "%Y-%m-%dT%H:%M:%S.%f%z")
                end_time = datetime.strptime(flow['end'], "%Y-%m-%dT%H:%M:%S.%f%z")
                duration = (end_time - start_time).total_seconds()

                # Extract relevant flow data
                features['Flow Duration'] = duration
                features['Total Fwd Packets'] = flow.get('pkts_toserver', 0)
                features['Total Backward Packets'] = flow.get('pkts_toclient', 0)
                features['Total Length of Fwd Packets'] = flow.get('bytes_toserver', 0)
                features['Total Length of Bwd Packets'] = flow.get('bytes_toclient', 0)

            features_list.append(features)

    # Create DataFrame from the list of dictionaries
    return pd.DataFrame(features_list)

# Load the pre-trained model, scaler, and PCA
scaler = joblib.load('scaler.pkl')
pca = joblib.load('pca.pkl')
model = joblib.load('isolation_forest_model.pkl')

# Extract features from eve.json
df_eve = extract_features_from_eve('/var/log/suricata/eve.json')

# Scale and transform the new data
df_scaled = scaler.transform(df_eve)
df_pca = pca.transform(df_scaled)

# Make predictions using the trained model
predictions = model.predict(df_pca)
anomalies = (predictions == -1).astype(int)  # 1 for anomaly, 0 for normal

# Write detected anomalies to the alert file
alert_file = '/home/tomas/IA_ML_Suricata/alerts.log'
with open(alert_file, 'a') as file:
    for index, anomaly in enumerate(anomalies):
        if anomaly:
            file.write(f"Anomaly detected in flow {index}!\n")

print("Anomaly detection completed. Alerts written to:", alert_file)
