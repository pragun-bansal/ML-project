import ssl
import socket



SERVER_IP = '127.0.0.1'
PORT_NUMBER = 8889
CHUNK_SIZE = 1024  # 1 KB chunks

# context                     = ssl.SSLContext()
# context.verify_mode         = ssl.CERT_REQUIRED
# context.load_verify_locations("./device.pem")

# ssl_context = ssl.create_default_context()
# ssl_context
# ssl_context.load_verify_locations("device.pem")

print("Test client sending packets to IP {0}, via port {1}\n".format(SERVER_IP, PORT_NUMBER))

mySocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ssl_socket = context.wrap_socket(mySocket)
ssl_socket.connect((SERVER_IP, PORT_NUMBER))

data_to_send = "Hello, Server! This is the client sending data."
ssl_socket.sendall(data_to_send.encode())
ssl_socket.close()

# Load the CSV data
# csv_path = 'titanic.csv'  # Change this to the path of your CSV file
# with open(csv_path, 'rb') as csv_file:
#     csv_data = csv_file.read()



# for i in range(1):
#     chunk_size = SIZE - len("CSV:")  
#     for i in range(0, len(csv_data), chunk_size):
#         chunk = csv_data[i: i + chunk_size]
#         mySocket.sendto(b'CSV:' + chunk, (SERVER_IP, PORT_NUMBER))

# mySocket.close()



