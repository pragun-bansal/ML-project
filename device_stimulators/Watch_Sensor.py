import requests
import json
import time
import random

# Replace with the server's URL where you want to send the data
server_url = 'http://localhost:8080'

while True:
    # Simulate wearable device data
    wearable_data = {
        "heart_rate": random.randint(60, 100),
        "steps": random.randint(0, 10000),
        "temperature": random.uniform(36.0, 37.5),
    }

    response = requests.post(f"{server_url}/wearable", json=wearable_data)

    if response.status_code == 200:
        print("Data sent successfully.")
    else:
        print(f"Failed to send data. Status code: {response.status_code}")

    time.sleep(60)
