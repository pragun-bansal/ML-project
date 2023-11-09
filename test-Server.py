import socket
import threading
from scapy.all import sniff, ARP, Dot11, EAPOL, ICMP
import http.server
import socketserver
from flask import Flask
from flask_sslify import SSLify
from zeroconf import Zeroconf, ServiceInfo
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.authorizers import DummyAuthorizer
import ntplib
from pyftpdlib.servers import FTPServer


# FTP Protocol
def handle_ftp():
    print("Starting FTP server on port 21")
    authorizer = DummyAuthorizer()
    authorizer.add_user("username", "password", "D:\Documents", perm="elradfmw")

    handler = FTPHandler
    handler.authorizer = authorizer
    server = FTPServer(("127.0.0.1", 21), handler)
    server.serve_forever()
    print("FTP server started. Listening on port 21")


def handle_tcp():
    def handle_tcp_client(client_socket):
        print("TCP Client connected")
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            # Process and respond to the data
            client_socket.send(b"Server received: " + data)
        client_socket.close()

    print("Starting TCP server on port 8888")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 8888))
    server_socket.listen(5)

    while True:
        client_socket, client_address = server_socket.accept()
        handle_tcp_client(client_socket)

def handle_udp():
    def handle_udp_server():
        print("Starting UDP server on port 8889")
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind(('0.0.0.0', 8889))

        while True:
            data, client_address = server_socket.recvfrom(1024)
            print(f"Received data from {client_address}")

            # Handle the received UDP data here

    handle_udp_server()

def handle_http():
    def start_http_server():
        with socketserver.TCPServer(("", 8080), http.server.SimpleHTTPRequestHandler) as httpd:
            print("Starting HTTP server on port 8080")
            httpd.serve_forever()

    start_http_server()


# def handle_arp():
#     def arp_handler(packet):
#         if ARP in packet:
#             if packet[ARP].op == 1:  # Request
#                 print(f"ARP Request: Who has {packet[ARP].pdst}? Tell {packet[ARP].psrc}")

#     sniff(filter="arp", prn=arp_handler)

# def handle_eapol():
#     def eapol_handler(packet):
#         if Dot11 in packet and packet[Dot11].type == 0 and EAPOL in packet:
#             print("EAPOL Packet Detected")
#             # Add your EAPOL handling logic here

#     sniff(filter="wlan type mgt subtype auth", prn=eapol_handler)

# def handle_icmp():
#     def icmp_handler(packet):
#         if ICMP in packet:
#             print("ICMP Packet Detected")
#             # Add your ICMP handling logic here

#     sniff(filter="icmp", prn=icmp_handler)

# def handle_icmp6():
#     def icmp6_handler(packet):
#         if ICMPv6 in packet:
#             print("ICMPv6 Packet Detected")
#             # Add your ICMPv6 handling logic here

#     sniff(filter="icmp6", prn=icmp6_handler)



# def handle_https():
#     app = Flask(__name__)
#     sslify = SSLify(app)

#     @app.route("/")
#     def hello():
#         return "Hello, World!"

#     app.run(host='0.0.0.0', port=443, ssl_context=('your_cert.pem', 'your_key.pem'))

# def handle_dhcp():
#     server = DHCPServer('0.0.0.0', 'eth0')  # Adjust the interface name
#     server.start()

# def handle_bootp():
#     # Handle BOOTP requests here
#     pass

# def handle_ssdp():
#     def handle_ssdp_server():
#         SSDP_PORT = 1900
#         SSDP_ADDR = "239.255.255.250"

#         sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#         sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#         sock.bind(("0.0.0.0", SSDP_PORT))

#         while True:
#             data, addr = sock.recvfrom(1024)
#             # Handle SSDP discovery requests and respond with appropriate SSDP messages

#     handle_ssdp_server()

# def handle_dns():
#     class DNSHandler:
#         def resolve(self, request, handler):
#             # Handle DNS request and return the appropriate DNS response
#             pass

#     udp_server = socketserver.UDPServer(('0.0.0.0', 53), DNSHandler)
#     udp_server.serve_forever()

# def handle_mdns():
#     zeroconf = Zeroconf()

#     info = ServiceInfo(
#         "_http._tcp.local.",
#         "My Web Server._http._tcp.local.",
#         address=b"192.168.1.100",
#         port=80,
#         properties={"path": "/path"},
#     )

#     zeroconf.register_service(info)

# def handle_ntp():
#     print("Starting NTP server on port 123")
#     ntp_server = ntplib.NTPServer()
#     ntp_server.serve_forever()

# Create separate threads for each protocol handler
threads = [
    # threading.Thread(target=handle_arp),
    # threading.Thread(target=handle_eapol),
    # threading.Thread(target=handle_icmp),
    # threading.Thread(target=handle_icmp6),
    threading.Thread(target=handle_tcp),
    threading.Thread(target=handle_udp),
    threading.Thread(target=handle_http),
    # threading.Thread(target=handle_https), 
    # threading.Thread(target=handle_dhcp),
    # threading.Thread(target=handle_bootp),
    # threading.Thread(target=handle_ssdp),
    # threading.Thread(target=handle_dns),
    # threading.Thread(target=handle_mdns),
    # threading.Thread(target=handle_ntp),
    threading.Thread(target=handle_ftp),
]

# Start all the threads
for thread in threads:
    thread.start()

# Wait for all threads to finish
for thread in threads:
    thread.join()
