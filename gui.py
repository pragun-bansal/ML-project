import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QPushButton
from PyQt5.QtGui import QFont
from scapy.all import *
from scapy.layers.http import HTTPRequest
import math
import csv
import numpy as np
import requests
import json
import time

url = "http://localhost:8601/v1/models/iot_model:predict"
headers = {"content-type": "application/json"}

ip = ['192.168.29.8']
label = ['Water_Sensor']

ip_hashmap = {}
for i in range(len(ip)):
    ip_hashmap[ip[i]] = label[i]


class LivePredictionGUI(QWidget):
    def __init__(self):
        super().__init__()

        self.initUI()

    def initUI(self):
        self.setWindowTitle('Live Prediction GUI')
        self.setGeometry(100, 100, 800, 600)
        self.setStyleSheet("background-color: #333; color: #FFF;")

        layout = QVBoxLayout()

        self.prediction_label = QLabel('Prediction: N/A')
        self.prediction_label.setFont(QFont('Arial', 16))
        layout.addWidget(self.prediction_label)

        self.start_button = QPushButton('Start Live Prediction')
        self.start_button.clicked.connect(self.start_sniffing)
        layout.addWidget(self.start_button)

        self.setLayout(layout)

    def start_sniffing(self):

        packet_queue = queue.Queue()

        conf.use_pcap = True
        conf.use_npcap = True

        temp_ipsrc, temp_ipdst, temp_sport, temp_dport, temp_proto = 0, 0, 0, 0, 0
        count = 0
        flag = 0
        sum1, sum = 0, 0
        c1, c = 0, 0
        ST = 0
        FV, FD, AFR, Tot_Sess, FPS = 0, 0, 0, 0, 0
        flag = 0
        t1, t2, t = 0, 0, 0

        start_timestamp = time.time()

      
        features_name = ['Arrival Time', 'ARP', 'LLC', 'EAPOL', "IP", 'ICMP', 'ICMP6', 'TCP', 'UDP', 'TCP_w_size',
                            'HTTP', 'HTTPS', 'DHCP', 'BOOTP', 'SSDP', 'DNS', 'MDNS', 'NTP', 'FTP', 'IP_padding',
                            'IP_ralert', 'Portcl_src', 'Portcl_dst', 'Pck_size', 'Pck_rawdata', "Entropy",
                            "Flow Volume", "Flow Per Second", "Flow Duration", "Average Flow Rate", "Label"]
        

        def port_class(port):
            if port == 21:
                return 4
            if 0 <= port <= 1023:
                return 1
            elif 1024 <= port <= 49151:
                return 2
            elif 49152 <= port <= 65535:
                return 3
            else:
                return 0

        def shannon(data):
            LOG_BASE = 2
            dataSize = len(data)
            ent = 0.0
            freq = {}
            for c in data:
                if c in freq:
                    freq[c] += 1
                else:
                    freq[c] = 1
            for key in freq.keys():
                f = float(freq[key]) / dataSize
                if f > 0:
                    ent = ent + f * math.log(f, LOG_BASE)
            return -ent

        def pre_entropy(payload):
            characters = []
            for i in payload:
                characters.append(i)
            return shannon(characters)

        def packet_feature_extractor(pkt):
            packet_queue.put(pkt)

        def process_packets():
            while True:
                try:
                    pkt = packet_queue.get(block=True, timeout=1) 
                    print("Packet Received", pkt.summary())
                    self.prediction_label.setText(f'Prediction Process: Hello')
                    nonlocal temp_dport, temp_sport, temp_proto, temp_ipdst, temp_ipsrc
                    nonlocal flag
                    nonlocal count, sum, sum1, c1, c, FV, FD, AFR, FPS
                    nonlocal t1, t2, t

                    layer_2_arp = 0
                    layer_2_llc = 0
                    source_ip = 0
                    destination_ip = 0
                    layer_3_eapol = 0
                    layer_3_ip = 0
                    layer_3_icmp = 0
                    layer_3_icmp6 = 0

                    layer_4_tcp = 0
                    layer_4_udp = 0
                    layer_4_tcp_ws = 0

                    layer_7_http = 0
                    layer_7_https = 0
                    layer_7_dhcp = 0
                    layer_7_bootp = 0
                    layer_7_ssdp = 0
                    layer_7_dns = 0
                    layer_7_mdns = 0
                    layer_7_ntp = 0
                    layer_7_ftp = 0

                    ip_padding = 0
                    ip_ralert = 0

                    port_class_src = 0
                    port_class_dst = 0

                    pck_size = 0
                    pck_rawdata = 0
                    entropy = 0
                    time_sec = 0

                    try:
                        pck_size = pkt.len
                    except:
                        pass

                    try:
                        if pkt[IP]:
                            layer_3_ip = 1
                            temp = str(pkt[IP].show)
                            if "ICMPv6" in temp:
                                layer_3_icmp6 = 1

                        temp = str(pkt[IP].dst)
                        source_ip = str(pkt[IP].src)
                        destination_ip = str(pkt[IP].dst)
                        port_class_src = port_class(pkt[IP].sport)
                        port_class_dst = port_class(pkt[IP].dport)
                    except:
                        pass

                    try:
                        if pkt[IP].ihl > 5:
                            if IPOption_Router_Alert(j):
                                pad = str(IPOption_Router_Alert(j).show)
                                if "Padding" in pad:
                                    ip_padding = 1
                                ip_ralert = 1
                    except:
                        pass

                    try:
                        if pkt[ICMP]:
                            layer_3_icmp = 1
                    except:
                        pass

                    try:
                        if pkt[Raw]:
                            pck_rawdata = 1
                    except:
                        pass

                    try:
                        if pkt[UDP]:
                            layer_4_udp = 1
                            if pkt[UDP].sport == 68 or pkt[UDP].sport == 67:
                                layer_7_dhcp = 1
                                layer_7_bootp = 1
                            if pkt[UDP].sport == 53 or pkt[UDP].dport == 53:
                                layer_7_dns = 1
                            if pkt[UDP].sport == 5353 or pkt[UDP].dport == 5353:
                                layer_7_mdns = 1
                            if pkt[UDP].sport == 1900 or pkt[UDP].dport == 1900:
                                layer_7_ssdp = 1
                            if pkt[UDP].sport == 123 or pkt[UDP].dport == 123:
                                layer_7_ntp = 1
                    except:
                        pass

                    try:
                        if pkt[TCP]:
                            layer_4_tcp = 1
                            layer_4_tcp_ws = pkt[TCP].window

                            x = port_class(pkt[TCP].sport)
                            y = port_class(pkt[TCP].dport)

                            if port_class_src == 0 and x != 0:
                                port_class_src = x

                            if port_class_dst == 0 and y != 0:
                                port_class_dst = y

                            if pkt[TCP].sport == 80 or pkt[TCP].dport == 80:
                                layer_7_http = 1
                            if pkt[TCP].sport == 443 or pkt[TCP].dport == 443:
                                layer_7_https = 1
                            if pkt[TCP].dport == 21 or pkt[TCP].sport == 21:
                                layer_7_ftp = 1
                    except:
                        pass

                    try:
                        if pkt[TCP] and pkt[IP]:
                            c = len(pkt)
                            t1 = pkt.time % 60
                            c1 = len(pkt[TCP].payload)

                            if (pkt[IP].src != temp_ipsrc or pkt[IP].dst != temp_ipdst or pkt[TCP].sport != temp_sport or
                                    pkt[TCP].dport != temp_dport or pkt[IP].proto != temp_proto):
                                flag = 1

                            if (flag == 1):
                                sum = c
                                sum1 = c1
                                t = t1
                                count = 1
                            else:
                                sum = sum + c
                                sum1 = sum1 + c1
                                t2 = pkt.time % 60
                                t = t + t1
                                count = count + 1

                            temp_ipsrc, temp_ipdst, temp_sport, temp_dport, temp_proto = pkt[IP].src, pkt[IP].dst, pkt[
                                TCP].sport, pkt[TCP].dport, pkt[IP].proto

                            FV = sum
                            FPS = sum1
                            FD = t
                            AFR = (FV / FD)
                    except:
                        pass

                    try:
                        if pkt[ARP]:
                            layer_2_arp = 1
                    except:
                        pass

                    try:
                        if pkt[LLC]:
                            layer_2_llc = 1
                    except:
                        pass

                    try:
                        if pkt[EAPOL]:
                            layer_3_eapol = 1
                    except:
                        pass

                    try:
                        entropy = pre_entropy(pkt[Raw].original)
                    except:
                        pass

                    if HTTPRequest in pkt:
                        source_ip = str(pkt[IP].src)
                        layer_7_http = 1

                    if source_ip in ip_hashmap:
                        label = ip_hashmap[source_ip]
                        time_sec = pkt.time - start_timestamp

                        input_data_np = np.array(
                            [layer_2_arp, layer_2_llc, layer_3_eapol, layer_3_ip, layer_3_icmp, layer_3_icmp6,
                                layer_4_tcp, layer_4_udp, layer_4_tcp_ws, layer_7_http, layer_7_https,
                                layer_7_dhcp, layer_7_bootp, layer_7_ssdp, layer_7_dns, layer_7_mdns,
                                layer_7_ntp, layer_7_ftp, ip_padding, ip_ralert, port_class_src,
                                port_class_dst, pck_size, pck_rawdata])
                        input_data_np = input_data_np.reshape(1, -1)
                        input_data = {"instances": input_data_np.tolist()}
                        json_data = json.dumps(input_data)
                        response = requests.post(url, data=json_data, headers=headers)
                        y = response.json()
                        for key, value in y.items():
                            res = np.array(value).argmax()
                            self.prediction_label.setText(f'Prediction: {res}')
                    else:
                        self.prediction_label.setText(f'Prediction {source_ip }')

                except Exception as e:
                    print(e)
                    pass
                print("Packet Processed", pkt.summary())
                time.sleep(10)
                self.prediction_label.setText(f'Prediction Process: Completed')


        processing_thread = threading.Thread(target=process_packets, daemon=True)
        processing_thread.start()
        sniff( count=10,prn=packet_feature_extractor)
        # self.prediction_label.setText(f'Prediction: N/A')


if __name__ == '__main__':
    app = QApplication(sys.argv)
    gui = LivePredictionGUI()
    gui.show()
    sys.exit(app.exec_())
