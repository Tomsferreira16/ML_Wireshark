#!/usr/bin/env python3
import pandas as pd
import numpy as np
import os
import glob
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
import joblib

# Folder path containing all JSON files
folder_path = "/home/tomas/IA_ML_Suricata"

# Step 1: Loading JSON files
print("Step 1: Loading JSON files...")
json_files = glob.glob(os.path.join(folder_path, "*.json"))

# Step 2: Concatenating DataFrames
print("Step 2: Concatenating DataFrames...")
df = pd.concat([pd.read_json(file, lines=True) for file in json_files], ignore_index=True)

# Step 3: Preprocessing data
print("Step 3: Preprocessing data...")
df.columns = df.columns.str.strip()  # Strip spaces from column names

# Select relevant numerical features (ignoring non-numerical fields like 'timestamp' and 'signature')
df = df.select_dtypes(include=[np.number])

# Handle missing or infinite values
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.fillna(df.mean(), inplace=True)

# Step 4: Scaling features
print("Step 4: Scaling features...")
scaler = StandardScaler()
df_scaled = scaler.fit_transform(df)

# Step 5: Applying PCA (optional for dimensionality reduction)
print("Step 5: Applying PCA...")
pca = PCA(n_components=0.95)
df_scaled_pca = pca.fit_transform(df_scaled)

# Step 6: Training Isolation Forest
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

# Step 7: Predicting anomalies
print("Step 7: Predicting anomalies...")
y_pred = clf.predict(df_scaled_pca)
y_pred = (y_pred == -1).astype(int)  # Convert predictions to binary (1 for anomaly, 0 for normal)

print("Process complete!")

import matplotlib.pyplot as plt
plt.scatter(df_scaled_pca[:, 0], df_scaled_pca[:, 1], c=y_pred, cmap='coolwarm')
plt.title("Anomaly Detection Results")
plt.xlabel("PCA Component 1")
plt.ylabel("PCA Component 2")
plt.show()
