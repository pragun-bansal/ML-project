import sys
import socket
import requests
import time
import random

SERVER_IP = '10.100.34.163'
PORT_NUMBER = 5000
SIZE = 1024

print("Test client sending images to IP {0}, via port {1}\n".format(SERVER_IP, PORT_NUMBER))

mySocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

while True:
    try:
        # Generate a random image URL from Lorem Picsum
        image_id = random.randint(1, 1000)
        image_url = f"https://picsum.photos/800/600/?image={image_id}"

        # Fetch the image from the internet
        response = requests.get(image_url)

        if response.status_code == 200:
            image_data = response.content

            for i in range(0, len(image_data), SIZE - len("IMG:")):
                chunk = image_data[i: i + SIZE - len("IMG:")]
                mySocket.sendto(b'IMG:' + chunk, (SERVER_IP, PORT_NUMBER))

            print(f"Sent image {image_id} to the server.")
        else:
            print(f"Failed to fetch image {image_id} from the internet.")

        time.sleep(5)  # Wait for 5 seconds before sending the next image

    except KeyboardInterrupt:
        print("Keyboard interrupt. Closing the client.")
        break

mySocket.close()
