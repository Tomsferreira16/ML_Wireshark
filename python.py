import pandas as pd
import json
import joblib

def extract_features_from_eve(json_file):
    with open(json_file) as f:
        data = json.load(f)
    
    features = []
    for entry in data:
        if 'flow' in entry:
            flow = entry['flow']
            features.append({
                'src_ip': entry.get('src_ip', None),
                'src_port': entry.get('src_port', None),
                'dst_ip': entry.get('dst_ip', None),
                'dst_port': entry.get('dst_port', None),
                'proto': entry.get('proto', None),
                'flow_duration': flow.get('age', None),  # Assuming 'age' is the duration
                'fwd_packets': flow.get('pkts_toserver', 0),
                'bwd_packets': flow.get('pkts_toclient', 0),
                'fwd_bytes': flow.get('bytes_toserver', 0),
                'bwd_bytes': flow.get('bytes_toclient', 0),
                'flow_bytes_per_second': flow.get('bytes_toserver', 0) / flow.get('age', 1)  # Basic calculation
            })
    
    return pd.DataFrame(features)

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

