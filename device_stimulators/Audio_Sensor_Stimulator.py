from ftplib import FTP
import time

# Replace with your FTP server details
ftp_server = "192.168.29.55" 
ftp_username = "username"
ftp_password = "password" 


voice_data_file = 'sound1.wav'


def send_voice_data_to_ftp(voice_data_file, ftp_server, ftp_username, ftp_password):
    with FTP(ftp_server) as ftp:
        ftp.login(ftp_username, ftp_password)

        with open(voice_data_file, 'rb') as file:
            ftp.storbinary(f'STOR {voice_data_file}', file)

        print(f"Voice data ({voice_data_file}) uploaded to FTP server.")

if __name__ == '__main__':
    while True:
        send_voice_data_to_ftp(voice_data_file, ftp_server, ftp_username, ftp_password)
        time.sleep(10)
