import joblib
import pandas as pd
import numpy as np
import json
import time
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os

# Load the trained model
clf = joblib.load('isolation_forest_model.pkl')

# Preprocessing functions (same as your training code)
scaler = StandardScaler()
pca = PCA(n_components=0.95)

# Function to log anomalies to a file
def log_anomaly(data):
    log_file = os.path.expanduser('~/anomaly_log.txt')  # Log file in home directory
    with open(log_file, 'a') as f:
        f.write(f"Anomaly detected: {data}\n")
    print("Anomaly logged to file!")

# Function to preprocess data and detect anomalies
def preprocess_and_predict(data):
    # Preprocess the data (same as your original code)
    data = pd.DataFrame([data])  # Convert dict to DataFrame for a single row
    data.columns = data.columns.str.strip()
    data = data.apply(pd.to_numeric, errors='coerce')
    data.replace([np.inf, -np.inf], np.nan, inplace=True)
    data.fillna(data.mean(), inplace=True)

    # Scaling and PCA
    data_scaled = scaler.transform(data)
    data_scaled_pca = pca.transform(data_scaled)

    # Predict anomaly
    y_pred = clf.predict(data_scaled_pca)
    return (y_pred == -1).astype(int)  # 1 for anomaly, 0 for benign

# File system event handler
class EveJsonHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path.endswith("eve.json"):
            with open(event.src_path, 'r') as f:
                for line in f:
                    try:
                        # Parse the JSON line
                        event_data = json.loads(line)
                        # You can modify this to select specific fields from the JSON
                        data = event_data.get('alert', {})  # Adjust based on your Suricata setup

                        if data:
                            # Preprocess and predict if anomaly
                            is_anomaly = preprocess_and_predict(data)
                            if is_anomaly:
                                log_anomaly(f"Data: {data} - Detected as anomaly")
                    except json.JSONDecodeError:
                        pass

# Set up the observer to watch the eve.json file
def start_monitoring():
    event_handler = EveJsonHandler()
    observer = Observer()
    observer.schedule(event_handler, path="/path/to/suricata/logs", recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)  # Keep running and monitoring
    except KeyboardInterrupt:
        observer.stop()

    observer.join()

if __name__ == "__main__":
    start_monitoring()
