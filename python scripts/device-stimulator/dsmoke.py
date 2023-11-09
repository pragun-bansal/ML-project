import socket
import random
import time

server_ip = '192.168.29.55'
server_port = 8888

while True:
    smoke_detected = random.choice([True, False])
    data = "Smoke Detected" if smoke_detected else "No Smoke"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((server_ip, server_port))
            s.send(data.encode())
            print(f"Sent data: {data}")
        except ConnectionRefusedError:
            print("Failed to connect to the server. Ensure the server is running.")

    time.sleep(4)  # Wait for 4 seconds before sending the next message
