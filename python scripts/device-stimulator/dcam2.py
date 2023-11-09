from ftplib import FTP
import cv2  # OpenCV for working with video frames
import time
import os

ftp_server = "localhost" 
ftp_username = "username"
ftp_password = "password" 
video_file = 'dnight.mp4'

def send_frames_to_ftp(video_file, ftp_server, ftp_username, ftp_password):
    # Open the video file
    cap = cv2.VideoCapture(video_file)

    # Connect to the FTP server
    with FTP(ftp_server) as ftp:
        ftp.login(ftp_username, ftp_password)
        
        frame_number = 0

        while True:
            ret, frame = cap.read()
            if not ret:
                break

            # Create a unique filename for each frame (you can customize this)
            frame_number += 1
            filename = f"frame_{frame_number}.jpg"

            # Save the frame as a temporary image file
            cv2.imwrite(filename, frame)

            # Upload the frame to the FTP server
            with open(filename, 'rb') as file:
                ftp.storbinary(f'STOR {filename}', file)

            # Remove the temporary image file
            os.remove(filename)

            # Add a delay between frame captures (you can customize this)
            time.sleep(1)

if __name__ == '__main__':
    send_frames_to_ftp(video_file, ftp_server, ftp_username, ftp_password)
