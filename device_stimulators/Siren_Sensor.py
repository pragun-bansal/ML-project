import socket
import time
import random

server_ip = '192.168.29.55'
server_port = 8888

while True:
    # Simulate siren status and event data
    siren_activated = random.choice([True, False])
    battery_status = random.uniform(0, 100)
    data = f"Siren Activated: {siren_activated}, Battery Status: {battery_status}%"

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((server_ip, server_port))
            s.send(data.encode())
            print(f"Sent data: {data}")
        except ConnectionRefusedError:
            print("Failed to connect to the server. Ensure the server is running.")

    time.sleep(5)  # Wait for 5 seconds before sending the next set of data
