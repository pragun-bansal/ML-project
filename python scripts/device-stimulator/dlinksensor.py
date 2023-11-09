import socket
import json
import time
import random

# Define the IP address and port of the TCP server
server_ip = '192.168.29.55'
server_port = 8888

while True:
    # Simulate collecting temperature and humidity data (replace with your data source)
    temperature = random.uniform(20.0, 30.0)
    humidity = random.uniform(40.0, 60.0)

    # Create a JSON payload
    data = {
        "temperature": temperature,
        "humidity": humidity
    }
    json_data = json.dumps(data)

    # Create a TCP socket and connect to the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((server_ip, server_port))

            # Send the JSON data
            s.sendall(json_data.encode())

            print(f"Sent data: {json_data}")

        except ConnectionRefusedError:
            print("Failed to connect to the server. Ensure the server is running.")

    # Close the socket
    s.close()

    # Sleep for a random time between 13 to 15 seconds
    sleep_time = random.uniform(13, 15)
    time.sleep(sleep_time)
