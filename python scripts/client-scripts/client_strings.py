import sys
import socket
import time
import random
import string

SERVER_IP = '10.100.34.163'
PORT_NUMBER = 5000
SIZE = 1024

print("Test client sending random strings to IP {0}, via port {1}\n".format(SERVER_IP, PORT_NUMBER))

mySocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def generate_random_string(length):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

while True:
    try:
        random_string = generate_random_string(SIZE - len("STR:"))
        mySocket.sendto(b'STR:' + random_string.encode(), (SERVER_IP, PORT_NUMBER))
        print(f"Sent random string: {random_string}")

        time.sleep(5)  # Wait for 5 seconds before sending the next random string

    except KeyboardInterrupt:
        print("Keyboard interrupt. Closing the client.")
        break

mySocket.close()
