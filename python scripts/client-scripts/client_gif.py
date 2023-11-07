import sys
import socket
import requests
import time
import random
import json

SERVER_IP = '10.100.82.108'
PORT_NUMBER = 5000
CHUNK_SIZE = 1024  # 1 KB chunks

# Replace with your Giphy API key
GIPHY_API_KEY = 'DFgApABQDKEeFh7CCq47DraA3qWwMZs9'

print("Test client sending GIFs to IP {0}, via port {1}\n".format(SERVER_IP, PORT_NUMBER))

mySocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def fetch_random_gif():
    try:
        # Fetch a random GIF using the Giphy API
        search_url = f"https://api.giphy.com/v1/gifs/random?api_key=DFgApABQDKEeFh7CCq47DraA3qWwMZs9&tag=&rating=g"
        response = requests.get(search_url)
        if response.status_code == 200:
            gif_data = json.loads(response.text)
            # print(gif_data)
            if 'data' in gif_data:
                gif_url = gif_data['data']['url']
                # print(gif_url)
                return gif_url
        print("Failed to fetch a random GIF.")
    except Exception as e:
        print(f"Error fetching GIF: {str(e)}")
    return None

while True:
    try:
        gif_url = fetch_random_gif()
        
        if gif_url:
            # Fetch the GIF from the internet
            response = requests.get(gif_url, stream=True)

            if response.status_code == 200:
                for chunk in response.iter_content(CHUNK_SIZE):
                    mySocket.sendto(b'GIF:' + chunk, (SERVER_IP, PORT_NUMBER))

                print(f"Sent GIF from {gif_url} to the server.")
            else:
                print(f"Failed to fetch GIF from {gif_url}.")

        time.sleep(5)  # Wait for 5 seconds before sending the next GIF

    except KeyboardInterrupt:
        print("Keyboard interrupt. Closing the client.")
        break

mySocket.close()