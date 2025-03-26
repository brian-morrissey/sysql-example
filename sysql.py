import requests
import time
import urllib.parse
import json
import os
import csv

# Function to flatten nested JSON objects (recursive)
def flatten_json(nested_json, parent_key='', sep='_'):
    items = {}
    for key, value in nested_json.items():
        new_key = f"{parent_key}{sep}{key}" if parent_key else key
        if isinstance(value, dict):  # If value is a dictionary, recursively flatten it
            items.update(flatten_json(value, new_key, sep=sep))
        elif isinstance(value, list):  # If value is a list, iterate over it and flatten it
            for i, sub_item in enumerate(value):
                items.update(flatten_json({f"{i}": sub_item}, new_key, sep=sep))
        else:
            items[new_key] = value
    return items

# Retrieve the authorization token from an environment variable
AUTHORIZATION_TOKEN = os.getenv("SYSDIG_AUTH_TOKEN")

if not AUTHORIZATION_TOKEN:
    print("Error: SYSDIG_AUTH_TOKEN environment variable is not set.")
    exit(1)

# The query to send to Sysdig API
QUERY = """
MATCH KubeWorkload HAS Container RUNS Image PACKAGE_INSTALLED_ON Package
  WHERE Package.name = 'github.com/opencontainers/runc' AND Package.path = '/nginx-ingress-controller' AND Package.version < 'v1.2.6'
  LIMIT 1000 OFFSET 0;
"""

# Encode the query
QUERYENCODED = urllib.parse.quote(QUERY)

# The Sysdig API endpoint URL
URL = "https://app.us3.sysdig.com/api/sysql/v1/query?&q="

# Initialize variables
offset = 0
total_items = []
headers = {'Authorization': f'Bearer {AUTHORIZATION_TOKEN}'}

# Loop to fetch data with increasing offsets
while True:
    # Adjust offset for each iteration
    query_with_offset = QUERY.replace("OFFSET 0", f"OFFSET {offset}")
    query_encoded = urllib.parse.quote(query_with_offset)

    # Send the GET request
    response = requests.get(URL + query_encoded, headers=headers)
    data = response.json()

    # If 'items' is null or empty, break the loop
    if 'items' not in data or not data['items']:
        break

    # Add the items from this response to the total list
    total_items.extend(data['items'])

    # Increment the offset for the next request
    offset += 1000

# Open a CSV file in write mode
with open('output.csv', mode='w', newline='', encoding='utf-8') as file:
    writer = csv.DictWriter(file, fieldnames=flatten_json(total_items[0]).keys())  # Flatten the first item to get the fieldnames
    writer.writeheader()  # Write the header row

    # Loop through the items, flatten them, and write them to the CSV file
    for item in total_items:
        try:
            flattened_item = flatten_json(item)  # Flatten the JSON item
            writer.writerow(flattened_item)  # Write the flattened item to the CSV file
        except KeyError as e:
            print(f"Missing attribute {e} in item.")

# Print the total number of items
print(f"\nTotal number of items retrieved: {len(total_items)}")
