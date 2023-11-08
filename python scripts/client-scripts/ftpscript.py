from ftplib import FTP

# Define FTP server details
HOSTNAME = "localhost"  # Use the same server address you used in your server script
USERNAME = "username"  # Use the same username defined in your server script
PASSWORD = "password"  # Use the same password defined in your server script

ftp_server = FTP(HOSTNAME, USERNAME, PASSWORD)

filename = "gfg.txt"

with open(filename, "rb") as file:
    ftp_server.storbinary(f"STOR {filename}", file)

ftp_server.dir()