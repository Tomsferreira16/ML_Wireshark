#!/usr/bin/env python3
import sys
import csv

# Get the label and file name from the command-line arguments
label = sys.argv[1]
file_name = sys.argv[2]

# Open the input CSV file
with open(file_name, mode='r') as file:
    content = csv.reader(file)
    
    # Read the first row (header) and append 'label' as a new column
    row0 = next(content)  # Use next() in Python 3
    row0.append('label')
    
    all_rows = [row0]  # Initialize the list with the updated header
    
    # Add the label to each subsequent row
    for item in content:
        item.append(label)
        all_rows.append(item)

# Define the new file name and save the updated CSV file
new_file_name = label + '_' + file_name
with open(new_file_name, mode='w', newline='') as new_file:
    writer = csv.writer(new_file, lineterminator='\n')
    writer.writerows(all_rows)

print(f"File saved as: {new_file_name}")

