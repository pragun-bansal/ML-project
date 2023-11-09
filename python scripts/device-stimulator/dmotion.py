import socket
import random

server_ip = '192.168.29.55'
server_port = 21

while True:
    motion_detected = random.choice([True, False])
    data = "Motion Detected" if motion_detected else "No Motion"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(data.encode(), (server_ip, server_port))
