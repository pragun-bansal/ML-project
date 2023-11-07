import sys
import socket
import requests
import time
import random
import json

SERVER_IP = '10.100.34.163'
PORT_NUMBER = 5000
CHUNK_SIZE = 1024 * 1024  # 1 MB chunks

# Replace with your YouTube API key
YOUTUBE_API_KEY = 'YOUR_API_KEY'

print("Test client sending videos to IP {0}, via port {1}\n".format(SERVER_IP, PORT_NUMBER))

mySocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def fetch_random_video():
    try:
        # Fetch a random video using the YouTube API
        search_url = f"https://www.googleapis.com/youtube/v3/search?key={YOUTUBE_API_KEY}&q=random&maxResults=1"
        response = requests.get(search_url)
        if response.status_code == 200:
            video_data = json.loads(response.text)
            if 'items' in video_data and len(video_data['items']) > 0:
                video_id = video_data['items'][0]['id']['videoId']
                video_url = f"https://www.youtube.com/watch?v={video_id}"
                return video_url
        print("Failed to fetch a random video.")
    except Exception as e:
        print(f"Error fetching video: {str(e)}")
    return None

while True:
    try:
        video_url = fetch_random_video()
        
        if video_url:
            # Fetch the video from the internet
            response = requests.get(video_url, stream=True)

            if response.status_code == 200:
                for chunk in response.iter_content(CHUNK_SIZE):
                    mySocket.sendto(b'VIDEO:' + chunk, (SERVER_IP, PORT_NUMBER))

                print(f"Sent video from {video_url} to the server.")
            else:
                print(f"Failed to fetch video from {video_url}.")

        time.sleep(5)  # Wait for 5 seconds before sending the next video

    except KeyboardInterrupt:
        print("Keyboard interrupt. Closing the client.")
        break

mySocket.close()
