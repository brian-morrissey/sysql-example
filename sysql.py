import requests
import time
import urllib.parse
import json
import os

# Retrieve the authorization token from an environment variable
AUTHORIZATION_TOKEN = os.getenv("SYSDIG_AUTH_TOKEN")

if not AUTHORIZATION_TOKEN:
    print("Error: SYSDIG_AUTH_TOKEN environment variable is not set.")
    exit(1)

# The query to send to Sysdig API
QUERY = """
MATCH Vulnerability AFFECTS KubeWorkload OPTIONAL MATCH KubeWorkload HAS Container RUNS Image PACKAGE_INSTALLED_ON Package
RETURN KubeWorkload.clusterName, KubeWorkload.namespaceName, KubeWorkload.name, Vulnerability.acceptedRisk,
       Vulnerability.cvssScore, Vulnerability.fixedInVersion, Vulnerability.name, Vulnerability.packageName,
       Vulnerability.packageVersion, Vulnerability.severity, Image.baseOS, Image.imageReference, Image.repository,
       Image.registry ORDER BY Vulnerability.lastModified LIMIT 1000 OFFSET 0;
"""

# Encode the query
QUERYENCODED = urllib.parse.quote(QUERY)

# The Sysdig API endpoint URL
URL = "https://app.us4.sysdig.com/api/sysql/v2/query?&q="

# Initialize variables
offset = 0
total_items = []
headers = {'Authorization': f'Bearer {AUTHORIZATION_TOKEN}'}

# Record the start time for total execution time
start_time = time.time()

# Loop to fetch data with increasing offsets
while True:
    # Adjust offset for each iteration
    query_with_offset = QUERY.replace("OFFSET 0", f"OFFSET {offset}")
    query_encoded = urllib.parse.quote(query_with_offset)

    # Start timing for this request
    request_start_time = time.time()

    # Send the GET request
    response = requests.get(URL + query_encoded, headers=headers)
    data = response.json()

    # Print out the execution time for this request
    request_end_time = time.time()
    print(f"Request for offset {offset} took {request_end_time - request_start_time:.2f} seconds")

    # If 'items' is null or empty, break the loop
    if 'items' not in data or not data['items']:
        break

    # Add the items from this response to the total list
    total_items.extend(data['items'])

    # Increment the offset for the next request
    offset += 1000

# Print out total execution time
end_time = time.time()
print(f"\nTotal execution time: {end_time - start_time:.2f} seconds")

# Loop through the items and print all the returned attributes
for item in total_items:
    try:
        print("\nItem details:")
        for key, value in item.items():
            print(f"{key}: {value}")
    except KeyError as e:
        print(f"Missing attribute {e} in item.")
