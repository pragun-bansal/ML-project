import socket
import random

server_ip = '192.168.29.55'
server_port = 8888

while True:
    ph_level = random.uniform(0.0, 14.0)
    turbidity = random.uniform(0.0, 100.0)
    data = f"pH: {ph_level}, Turbidity: {turbidity} NTU"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(data.encode(), (server_ip, server_port))
