#!/usr/bin/env python3
import pandas as pd
import numpy as np
import os
import glob
import json  # Add this import for JSON parsing
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
import joblib

# Folder path containing all JSON files
folder_path = "ML_dataset_JSON"

# Feature extraction function
def extract_features(log_entry):
    features = {}

    # Extract general flow information
    features["flow_id"] = log_entry.get("flow_id", np.nan)
    features["pcap_cnt"] = log_entry.get("pcap_cnt", np.nan)
    features["src_ip"] = log_entry.get("src_ip", np.nan)
    features["src_port"] = log_entry.get("src_port", np.nan)
    features["dest_ip"] = log_entry.get("dest_ip", np.nan)
    features["dest_port"] = log_entry.get("dest_port", np.nan)
    features["proto"] = log_entry.get("proto", np.nan)

    # Extract DNS-specific fields
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

    # Handle DNS answers
    features["dns.answers"] = len(dns.get("answers", [])) if "answers" in dns else np.nan

    # Handle DNS grouped (CNAME, A records, etc.)
    grouped = dns.get("grouped", {})
    features["dns.grouped.CNAME"] = len(grouped.get("CNAME", [])) if "CNAME" in grouped else np.nan
    features["dns.grouped.A"] = len(grouped.get("A", [])) if "A" in grouped else np.nan

    # Handle authorities
    authorities = dns.get("authorities", [])
    features["dns.authorities_count"] = len(authorities)

    # Additional fields (ICMP and other potential data)
    features["icmp_code"] = log_entry.get("icmp_code", np.nan)
    features["icmp_type"] = log_entry.get("icmp_type", np.nan)
    features["response_icmp_code"] = log_entry.get("response_icmp_code", np.nan)
    features["response_icmp_type"] = log_entry.get("response_icmp_type", np.nan)
    features["tx_id"] = log_entry.get("tx_id", np.nan)

    return features


# Step 1: Loading JSON files
print("Step 1: Loading JSON files...")
json_files = glob.glob(os.path.join(folder_path, "*.json"))

# Step 2: Extracting features from each JSON file
print("Step 2: Extracting features from JSON files...")
data = []

for file in json_files:
    with open(file, 'r') as f:
        for line in f:
            log_entry = json.loads(line)  # Use json module for parsing
            features = extract_features(log_entry)
            data.append(features)

# Step 3: Converting extracted features into a DataFrame
df = pd.DataFrame(data)

# Step 4: Preprocessing data
print("Step 3: Preprocessing data...")
df.columns = df.columns.str.strip()  # Strip spaces from column names

# Select only relevant numerical features
relevant_features = [
    "flow_id", "pcap_cnt", "src_ip", "src_port", "dest_ip", "dest_port", "proto",
    "dns.version", "dns.type", "dns.id", "dns.flags", "dns.qr", "dns.rd", "dns.ra",
    "dns.rrname", "dns.rrtype", "dns.rcode", "icmp_code", "icmp_type", 
    "response_icmp_code", "response_icmp_type", "tx_id"
]
df = df[relevant_features]

# Select relevant numerical features (ignoring non-numerical fields like 'timestamp' and 'signature')
df = df.select_dtypes(include=[np.number])

# Handle missing or infinite values
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.fillna(df.mean(), inplace=True)

# Step 5: Scaling features
print("Step 4: Scaling features...")
scaler = StandardScaler()
df_scaled = scaler.fit_transform(df)

# Step 6: Applying PCA (optional for dimensionality reduction)
print("Step 5: Applying PCA...")
pca = PCA(n_components=0.95)
df_scaled_pca = pca.fit_transform(df_scaled)

# Step 7: Training Isolation Forest
print("Step 6: Training Isolation Forest...")
clf = IsolationForest(
    n_estimators=200,
    contamination=0.05,  # Adjust contamination as needed (percentage of expected anomalies)
    random_state=42,
    n_jobs=-1,
    max_samples='auto',
    bootstrap=True
)
clf.fit(df_scaled_pca)  # Fit the model with the data

# Step 8: Predicting anomalies
print("Step 7: Predicting anomalies...")
y_pred = clf.predict(df_scaled_pca)
y_pred = (y_pred == -1).astype(int)  # Convert predictions to binary (1 for anomaly, 0 for normal)

# Save the trained model after evaluation
print("Step 8: Saving the trained model...")
joblib.dump(clf, 'isolation_forest_model.pkl')  # Save the model to a file
# Save the scaler and PCA to disk
joblib.dump(scaler, 'scaler.pkl')  # Save scaler
joblib.dump(pca, 'pca.pkl')  # Save PCA model

# Step 9: Visualizing results
import matplotlib.pyplot as plt
plt.scatter(df_scaled_pca[:, 0], df_scaled_pca[:, 1], c=y_pred, cmap='coolwarm')
plt.title("Anomaly Detection Results")
plt.xlabel("PCA Component 1")
plt.ylabel("PCA Component 2")
plt.show()

print("Process complete!")