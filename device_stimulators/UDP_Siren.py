import socket
import time
import random

server_ip = '192.168.29.55'
server_port = 8888

while True:
    siren_activated = random.choice([True, False])
    battery_status = random.uniform(0, 100)
    data = f"Siren Activated: {siren_activated}, Battery Status: {battery_status}%"

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        server_address = (server_ip, server_port)
        s.sendto(data.encode(), server_address)
        print(f"Sent data: {data} to {server_ip}:{server_port}")

    time.sleep(5)  # Wait for 5 seconds before sending the next set of data
