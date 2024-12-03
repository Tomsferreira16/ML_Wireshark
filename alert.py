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

# Features used during model training (make sure these match your model's training features)
trained_features = [
    "flow_id", "pcap_cnt", "src_ip", "src_port", "dest_ip", "dest_port", "proto",
    "dns.version", "dns.type", "dns.id", "dns.flags", "dns.qr", "dns.rd", "dns.ra",
    "dns.rrname", "dns.rrtype", "dns.rcode", "dns.answers"
]

# Function to log alert messages to a file
def log_alert(message):
    if not os.path.exists(alerts_file_path):
        with open(alerts_file_path, 'w') as file:
            file.write("Alert Log Initialized\n")
    
    with open(alerts_file_path, 'a') as file:
        file.write(f"{message}\n")

# Function to extract relevant features from a Suricata log entry
def extract_features(log_entry):
    # Initialize an empty dictionary for the features
    features = {}

    # Extract relevant fields (assuming they are present in the log entry)
    features["flow_id"] = log_entry.get("flow_id", np.nan)
    features["pcap_cnt"] = log_entry.get("pcap_cnt", np.nan)
    features["src_ip"] = log_entry.get("src_ip", np.nan)
    features["src_port"] = log_entry.get("src_port", np.nan)
    features["dest_ip"] = log_entry.get("dest_ip", np.nan)
    features["dest_port"] = log_entry.get("dest_port", np.nan)
    features["proto"] = log_entry.get("proto", np.nan)
    
    # DNS-related fields (ensure to handle missing data)
    dns = log_entry.get("dns", {})
    features["dns.version"] = dns.get("version", np.nan)
    features["dns.type"] = dns.get("type", np.nan)
    features["dns.id"] = dns.get("id", np.nan)
    features["dns.flags"] = dns.get("flags", np.nan)
    features["dns.qr"] = dns.get("qr", np.nan)
    features["dns.rd"] = dns.get("rd", np.nan)
    features["dns.ra"] = dns.get("ra", np.nan)
    features["dns.rrname"] = dns.get("rrname", np.nan)
    features["dns.rrtype"] = dns.get("rrtype", np.nan)
    features["dns.rcode"] = dns.get("rcode", np.nan)
    
    # Handle answers (if present)
    answers = dns.get("answers", [])
    features["dns.answers"] = len(answers) if answers else np.nan

    return features

# Function to process Suricata logs and predict anomalies
def process_log_entry(log_entry):
    try:
        # Extract features from the log entry
        features = extract_features(log_entry)

        # Convert the extracted features into a DataFrame
        df = pd.DataFrame([features])

        # Ensure the correct features are available, if any are missing, fill with NaN or 0
        missing_features = set(trained_features) - set(df.columns)
        for feature in missing_features:
            df[feature] = np.nan
        
        # Reorder columns to match the trained model features
        df = df[trained_features]

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
