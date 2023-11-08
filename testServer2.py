import socket
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from datetime import datetime

# Constants
PORTS = {
    "HTTP": 80,
    "HTTPS": 443,
    "DNS": 53,
    "NTP": 123,
}
INTERFACE = "0.0.0.0"

# UDP server for handling NTP requests
def handle_ntp():
    udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_server.bind((INTERFACE, PORTS["NTP"]))

    while True:
        data, addr = udp_server.recvfrom(1024)
        print(f"Received NTP data from {addr}: {data}")

# HTTP request handler
class SimpleRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"Hello, this is a simple HTTP server!")

# HTTP server for handling HTTP and HTTPS requests
class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    pass

def handle_http_https():
    http_server = ThreadingHTTPServer((INTERFACE, PORTS["HTTP"]), SimpleRequestHandler)
    http_server.socket = ssl.wrap_socket(http_server.socket, keyfile="server-key.key", certfile="server-cert.crt", server_side=True)
    http_server.serve_forever()

# UDP server for handling DNS requests
def handle_dns():
    udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_server.bind((INTERFACE, PORTS["DNS"]))

    while True:
        data, addr = udp_server.recvfrom(1024)
        print(f"Received DNS data from {addr}: {data}")

if __name__ == "__main__":
    ntp_thread = threading.Thread(target=handle_ntp)
    http_https_thread = threading.Thread(target=handle_http_https)
    dns_thread = threading.Thread(target=handle_dns)

    ntp_thread.start()
    http_https_thread.start()
    dns_thread.start()

    ntp_thread.join()
    http_https_thread.join()
    dns_thread.join()
