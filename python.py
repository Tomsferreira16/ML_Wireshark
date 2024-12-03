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
            try:
                data = json.loads(line.strip())
                
                # Initialize the features dictionary with missing fields set to 0
                features = {
                    'Flow Duration': 0,
                    'Total Fwd Packets': 0,
                    'Total Backward Packets': 0,
                    'Total Length of Fwd Packets': 0,
                    'Total Length of Bwd Packets': 0,
                    'Packets/s': 0,
                    'Bytes/s': 0,
                    'ACK Flag Count': 0,  # Placeholder
                    'SYN Flag Count': 0,  # New flag example
                }

                if 'flow' in data:
                    flow = data['flow']
                    # Extract start and end times
                    start_time = datetime.strptime(flow.get('start', '1970-01-01T00:00:00.000000+0000'), "%Y-%m-%dT%H:%M:%S.%f%z")
                    end_time = datetime.strptime(flow.get('end', '1970-01-01T00:00:00.000000+0000'), "%Y-%m-%dT%H:%M:%S.%f%z")
                    duration = (end_time - start_time).total_seconds() or 1  # Avoid division by zero
                    
                    # Calculate flow metrics
                    pkts_toserver = flow.get('pkts_toserver', 0)
                    pkts_toclient = flow.get('pkts_toclient', 0)
                    bytes_toserver = flow.get('bytes_toserver', 0)
                    bytes_toclient = flow.get('bytes_toclient', 0)
                    
                    # Populate features
                    features['Flow Duration'] = duration
                    features['Total Fwd Packets'] = pkts_toserver
                    features['Total Backward Packets'] = pkts_toclient
                    features['Total Length of Fwd Packets'] = bytes_toserver
                    features['Total Length of Bwd Packets'] = bytes_toclient
                    features['Packets/s'] = (pkts_toserver + pkts_toclient) / duration
                    features['Bytes/s'] = (bytes_toserver + bytes_toclient) / duration

                # Extract TCP flags if available
                if 'tcp' in data:
                    tcp = data['tcp']
                    features['ACK Flag Count'] = 1 if tcp.get('ack', False) else 0
                    features['SYN Flag Count'] = 1 if tcp.get('syn', False) else 0

                features_list.append(features)
            except (json.JSONDecodeError, KeyError) as e:
                print(f"Error processing line: {e}")
                continue  # Skip invalid lines gracefully

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
