import sys
import socket
import threading
import http.server
import socketserver
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.servers import FTPServer
from PyQt5.QtWidgets import QApplication, QMainWindow, QFrame, QHBoxLayout, QPushButton, QTextEdit, QVBoxLayout, QGridLayout, QLabel, QWidget
from PyQt5.QtCore import Qt
import logging


class ServerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.init_server_threads()

    def init_ui(self):
        self.server_config = {
            "HTTP": {"port": 8080},
            "TCP": {"port": 5000},
            "UDP": {"port": 5005},
            "FTP": {"ip": "192.168.29.55", "port": 21},
        }

        self.setWindowTitle("Server")
        self.setWindowState(Qt.WindowMaximized)
        self.setStyleSheet("background-color: #1A1B1B;")
        
        central_widget = QFrame(self)
        self.setCentralWidget(central_widget)

        left_side = QHBoxLayout()
        right_side = QHBoxLayout()
        
        label_box = QWidget(self)
        label_box.setStyleSheet("background-color: #303130; border-radius: 10px; padding: 10px; margin: 5px;")


        team_label = QLabel("Team Name: Shivam Gupta, Yash Rajoria, Pragun Bansal")
        project_label = QLabel("Project: IOT DEVICE CLASSIFIER")
        mentor_label = QLabel("Mentor: Dr. Gaurav Singhal")

        label_style = "font-size: 22px; color: white; padding: 10px; font-weight: bold;"
        team_label.setStyleSheet(label_style)
        project_label.setStyleSheet(label_style)
        mentor_label.setStyleSheet(label_style)

        labelBox = QVBoxLayout()
        labelBox.addWidget(team_label)
        labelBox.addWidget(project_label)
        labelBox.addWidget(mentor_label)
        labelBox.setSpacing(0)
        label_box.setContentsMargins(0, 0, 0, 0)
        label_box.setMaximumHeight(250)

        label_box.setLayout(labelBox)

        right_side.addWidget(label_box)


        layout = QVBoxLayout()
        layout.addLayout(left_side, 2)
        layout.addLayout(right_side, 3)
        editor_layout = QGridLayout()
        right_side.addLayout(editor_layout)



        self.server_buttons = {}
        self.server_logs = {}

        row = 0
        col = 0

        for server_type, config in self.server_config.items():
            button = QPushButton(f"Start {server_type} Server", self)
            button.setStyleSheet("background-color: #303130; color: white; font-size: 16px; padding: 10px 20px;")
            button.clicked.connect(lambda _, server_type=server_type: self.start_server(server_type))
            log = QTextEdit()
            log.setStyleSheet(
                "background-color: #303130; color: white; font-size: 16px;" 
                "padding: 10px 20px; color: yellow; font-weight: bold; border: none; border-radius: 10px;" )
            log.setReadOnly(True)

            self.server_buttons[server_type] = button
            self.server_logs[server_type] = log

            left_side.addWidget(button)

            if col % 2 == 0 and col > 0:
                row += 1
                col = 0
                
            editor_layout.addWidget(button, row, col)
            editor_layout.addWidget(log, row, col + 1)

            col += 2

        central_widget.setLayout(layout)

    def init_server_threads(self):
        self.server_threads = {}
        self.server_stop_flags = {}

        for server_type, config in self.server_config.items():
            self.server_threads[server_type] = threading.Thread(target=self.start_server_type, args=(server_type,))
            self.server_stop_flags[server_type] = threading.Event()

    def start_server(self, server_type):
        if self.server_buttons[server_type].text() == f"Start {server_type} Server":
            self.server_threads[server_type].start()
            self.server_buttons[server_type].setEnabled(False)
            self.server_buttons[server_type].setText(f"{server_type} Server Running")
            self.server_buttons[server_type].setStyleSheet("background-color: #313131; color: white; font-size: 16px; padding: 10px 20px; opacity: 0.5;")
        else:
            self.server_stop_flags[server_type].set()
            self.server_threads[server_type].join()
            self.server_stop_flags[server_type].clear()
            self.server_buttons[server_type].setEnabled(True)
            self.server_buttons[server_type].setText(f"Start {server_type} Server")
            self.server_buttons[server_type].setStyleSheet("background-color: #303130; color: white; font-size: 16px; padding: 10px 20px;")

    def start_server_type(self, server_type):
        config = self.server_config[server_type]
        log = self.server_logs[server_type]

        def log_event(msg):
            try:
                if type(msg) == logging.LogRecord:
                    msg = msg.getMessage()
                log.append(msg)
                log.verticalScrollBar().setValue(log.verticalScrollBar().maximum())
            except:
                pass

        if server_type == "HTTP":
            self.start_http_server(config, log, log_event)
        elif server_type == "TCP":
            self.start_tcp_server(config, log, log_event)
        elif server_type == "UDP":
            self.start_udp_server(config, log, log_event)
        elif server_type == "FTP":
            self.start_ftp_server(config, log, log_event)

    def start_http_server(self, config, log, log_event):
        port = config["port"]
        log_event(f"Starting HTTP server on port {port}")
        with socketserver.TCPServer(("", port), http.server.SimpleHTTPRequestHandler) as httpd:
            log_event(f"HTTP server started. Listening on port {port}")
            httpd.serve_forever()

    def start_tcp_server(self, config, log, log_event):
        port = config["port"]
        log_event(f"Starting TCP server on port {port}")
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('0.0.0.0', port))
        server_socket.listen(5)
        log_event(f"TCP server started. Listening on port {port}")

        while not self.server_stop_flags["TCP"].is_set():
            client_socket, client_address = server_socket.accept()
            log_event(f"TCP Client connected from {client_address}")

            def handle_tcp_client(client_socket):
                while not self.server_stop_flags["TCP"].is_set():
                    data = client_socket.recv(1024)
                    log_event(f"Received data: {data}")

                    if not data:
                        break

                    response = b"Server received: " + data
                    log_event(f"Sending response: {response}")
                    client_socket.send(response)

                client_socket.close()
                log_event("TCP Client disconnected")

            threading.Thread(target=handle_tcp_client, args=(client_socket,)).start()

    def start_udp_server(self, config, log, log_event):
        port = config["port"]
        log_event(f"Starting UDP server on port {port}")
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind(('0.0.0.0', port))

        while not self.server_stop_flags["UDP"].is_set():
            data, client_address = server_socket.recvfrom(1024)
            log_event(f"Received data from {client_address}")

    def start_ftp_server(self, config, log, log_event):
        ip = config["ip"]
        port = config["port"]

        def emit_ftp_log(msg):
            log_event(msg)

        pyftpdlib_logger = logging.getLogger("pyftpdlib")
        pyftpdlib_logger.setLevel(logging.INFO)
        pyftpdlib_logger.handlers = [logging.StreamHandler()]
        pyftpdlib_logger.handlers[0].emit = emit_ftp_log
        
        log_event(f"Starting FTP server on port {port}")
        authorizer = DummyAuthorizer()
        authorizer.add_user("username", "password", "D:\Documents", perm="elradfmw")

        handler = FTPHandler
        handler.authorizer = authorizer
        server = FTPServer((ip, port), handler)
        server.handler.log = lambda msg: log_event(logging.Formatter(msg))
        server.serve_forever()
        log_event(f"FTP server started. Listening on port {port}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    server_app = ServerApp()
    server_app.show()
    sys.exit(app.exec_())
