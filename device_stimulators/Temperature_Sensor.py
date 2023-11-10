import socket
import json
import time
import random

server_ip = '127.0.0.1'
server_port = 4004

while True:
    temperature = random.uniform(20.0, 30.0)
    humidity = random.uniform(40.0, 60.0)

    data = {
        "temperature": temperature,
        "humidity": humidity
    }

    json_data = json.dumps(data)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((server_ip, server_port))
            s.sendall(json_data.encode())
            print(f"Sent data: {json_data}")

        except ConnectionRefusedError:
            print("Failed to connect to the server. Ensure the server is running.")


    s.close()

    sleep_time = 7
    time.sleep(sleep_time)
