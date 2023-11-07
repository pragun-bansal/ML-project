from socket import socket, gethostbyname, AF_INET, SOCK_DGRAM, SOCK_STREAM
import sys
import ssl

PORT_NUMBER = 5000
SIZE = 1024*1024
hostName = gethostbyname( '0.0.0.0' )

server_socket  = socket( AF_INET, SOCK_STREAM )
server_socket.bind( (hostName, PORT_NUMBER) )
server_socket.listen()

ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
ssl_context.load_cert_chain(certfile="device.pem", keyfile="device.key")

print (f"Test server listening on port {PORT_NUMBER}\n")

# while True:
#         x = mySocket.recvfrom(SIZE)
#         print(x)
#         if x[0].startswith(b'CSV:'):
#             print(x[0])
#             ip_address = x[1][0]
#             print(ip_address)
        
while True:
    client_socket, client_address = server_socket.accept()
    print(client_socket,client_address)
    with ssl_context.wrap_socket(client_socket, server_side=True) as secure_conn:
        print(secure_conn)
        data = secure_conn.recv(SIZE)
        print(data.decode())


    # ssl_socket = ssl_context.wrap_socket(client_socket, server_side=True)

    # print(f"Connection from {client_address}")

    # received_data = b''
    # while True:
    #     data = ssl_socket.recv(SIZE)
    #     if not data:
    #         break
    #     received_data += data

    # # Handle the received data
    # print(received_data.decode())

    # ssl_socket.close()

server_socket.close()



 

# from scapy.all import IP, TCP
# import socket

# PORT_NUMBER = 5000
# BUFFER_SIZE = 4096

# server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# server_socket.bind(('0.0.0.0', PORT_NUMBER))
# server_socket.listen(1)

# print(f"Server listening on port {PORT_NUMBER}\n")

# while True:
#     client_socket, client_address = server_socket.accept()
#     print(f"Connection from {client_address}")
    
#     received_data = b''
#     while True:
#         data = client_socket.recv(BUFFER_SIZE)
#         if not data:
#             break
#         received_data += data
    
#     client_socket.close()
    
#     # Use Scapy to dissect the received data
#     packet = IP(received_data) / TCP(received_data)
    
#     # Print packet details
#     print(packet.summary())
#     packet.show()

# server_socket.close()
