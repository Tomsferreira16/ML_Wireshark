import json
import pandas as pd

# Path to the input and output files
input_file = '/var/log/suricata/eve.json'
output_file = '/home/tomas/IA_ML_Suricata/eve_data.csv'

# List to store parsed data
data_list = []

# Read the eve.json file line by line
with open(input_file, 'r') as file:
    for line in file:
        try:
            data = json.loads(line.strip())
            data_list.append(data)  # Add each JSON object to the list
        except json.JSONDecodeError:
            print("Error decoding line:", line)

# Convert the list of dictionaries to a DataFrame
df = pd.DataFrame(data_list)

# Save the DataFrame as a CSV file
df.to_csv(output_file, index=False)

print(f"CSV file created successfully: {output_file}")
