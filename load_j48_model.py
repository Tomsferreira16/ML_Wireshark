import joblib
import pandas as pd

# Load the trained model
model = joblib.load("j48_model.pkl")

# Load the new data (ensure this file exists)
file_path = "new_data.csv"  # Replace with the path to your new data file
data = pd.read_csv(file_path)

# Ensure all required columns are present
expected_columns = [
    "ip.src", "ip.dst", "ip.len", "ip.flags.df", "ip.flags.mf", "ip.fragment", 
    "ip.fragment.count", "ip.fragments", "ip.ttl", "ip.proto", "tcp.window_size", 
    "tcp.ack", "tcp.seq", "tcp.len", "tcp.stream", "tcp.urgent_pointer", 
    "tcp.flags", "tcp.analysis.ack_rtt", "tcp.segments", "tcp.reassembled.length", 
    "http.request", "udp.port", "frame.time_relative", "frame.time_delta", 
    "tcp.time_relative", "tcp.time_delta"
]

# Check if the file has all required columns
missing_columns = set(expected_columns) - set(data.columns)
if missing_columns:
    raise ValueError(f"The following columns are missing in the input file: {missing_columns}")

# Predict the class for each row
predictions = model.predict(data)

# Add predictions to the dataset
data["Prediction"] = predictions

# Save the predictions to a new file
output_path = "predicted_data.csv"
data.to_csv(output_path, index=False)

print(f"Predictions saved to {output_path}")
