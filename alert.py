#!/usr/bin/env python3
import pandas as pd
import numpy as np
import os
import json
import time
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
import joblib

# File paths
suricata_log_path = "/var/log/suricata/eve.json"
alerts_file_path = "/home/tomas/IA_ML_Suricata/alerts.txt"

# Load pre-trained models and scaler
clf = joblib.load('/home/tomas/IA_ML_Suricata/isolation_forest_model.pkl')
scaler = joblib.load('/home/tomas/IA_ML_Suricata/scaler.pkl')
pca = joblib.load('/home/tomas/IA_ML_Suricata/pca.pkl')

# Feature columns used during model training (set this to match your model's training features)
trained_features = ['dest_port', 'flow_id', 'icmp_code', 'icmp_type', 'pcap_cnt', 'response_icmp_code', 'response_icmp_type', 'other_feature_1', 'other_feature_2']

# Function to log alert messages to a file
def log_alert(message):
    if not os.path.exists(alerts_file_path):
        with open(alerts_file_path, 'w') as file:
            file.write("Alert Log Initialized\n")
    
    with open(alerts_file_path, 'a') as file:
        file.write(f"{message}\n")

# Function to process Suricata logs and predict anomalies
def process_log_entry(log_entry):
    try:
        # Normalize the JSON log entry to a pandas DataFrame
        df = pd.json_normalize(log_entry)

        # Select only the relevant features (ensure they match the features used during training)
        df = df[trained_features] if all(feature in df.columns for feature in trained_features) else pd.DataFrame(columns=trained_features)

        # Handle missing or infinite values by filling with zeros (or any default value)
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.fillna(0, inplace=True)

        # Scale features and apply PCA
        df_scaled = scaler.transform(df)
        df_scaled_pca = pca.transform(df_scaled)

        # Predict anomaly using Isolation Forest
        y_pred = clf.predict(df_scaled_pca)
        
        # Convert prediction to binary (1 for anomaly, 0 for normal)
        if y_pred == -1:  # If it's an anomaly
            log_alert("Anomaly detected in Suricata log entry!")
            return True  # Return True to indicate an anomaly
        else:
            return False  # Return False if no anomaly

    except Exception as e:
        print(f"Error processing log entry: {e}")
        return False

# Function to monitor the eve.json log file and process new entries
def monitor_suricata_log():
    print("Monitoring Suricata logs for anomalies...")
    
    # Open Suricata log file and seek to the end (live mode)
    with open(suricata_log_path, 'r') as log_file:
        log_file.seek(0, os.SEEK_END)  # Move to the end of the file to start live reading

        while True:
            line = log_file.readline()
            if line:
                try:
                    log_entry = json.loads(line.strip())
                    # Process the log entry for anomaly detection
                    process_log_entry(log_entry)
                except json.JSONDecodeError:
                    print("Error decoding JSON log entry.")
            time.sleep(1)  # Sleep to prevent excessive CPU usage

# Run the log monitoring function
if __name__ == "__main__":
    monitor_suricata_log()
