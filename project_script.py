import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton
from PyQt5.QtCore import QThread, pyqtSignal
from scapy.all import *
import time
import math
import csv

conf.use_pcap = True
conf.use_npcap = True

temp_ipsrc, temp_ipdst, temp_sport, temp_dport, temp_proto = 0, 0, 0, 0, 0
count=0
flag=0
sum1,sum=0,0	
c1,c = 0,0
ST=0
FV,FD,AFR,Tot_Sess,FPS=0,0,0,0,0
flag = 0
t1,t2,t=0,0,0

# storign current timestamp so that we can store relative time in packet feature
start_timestamp  = time.time()

class PacketCaptureThread(QThread):
    packet_received = pyqtSignal(object)

    def run(self):

        with open('x.csv', 'w', newline='') as csv_file:
            features_name=['SRC IP','Arrival Time','ARP','LLC','EAPOL',"IP",'ICMP','ICMP6','TCP','UDP','TCP_w_size','HTTP','HTTPS','DHCP','BOOTP','SSDP','DNS','MDNS','NTP','IP_padding','IP_ralert','Portcl_src','Portcl_dst','Pck_size','Pck_rawdata',"Entropy","Flow Volume","Flow Per Second","Flow Duration","Average Flow Rate"] 
            csv_writer = csv.writer(csv_file)
            csv_writer.writerow(features_name)
            print("CSV file created and headers written")
            
            def port_class(port):
                if port== 59655:
                    print("FTP")
                    return 4
                if 0 <= port <= 1023:
                    return 1
                elif  1024 <= port <= 49151 :
                    return 2
                elif 49152 <=port <= 65535 :
                    return 3
                else:
                    return 0

            def shannon(data):
                LOG_BASE = 2
                dataSize = len(data)
                ent = 0.0
                freq={} 
                for c in data:
                    if c in freq:
                        freq[c] += 1
                    else:
                        freq[c] = 1
                for key in freq.keys():
                    f = float(freq[key])/dataSize
                    if f > 0: 
                        ent = ent + f * math.log(f, LOG_BASE)
                return -ent
        
            def pre_entropy(payload):
                '''
                Pre-Entropy is a measure of the amount of randomness in a packet payload.
                '''
                characters=[]
                for i in payload:
                    characters.append(i)
                return shannon(characters)
            
            def packet_feature_extractor(pkt):      
                global csv_writer
                global csv_file
                global temp_dport, temp_sport, temp_proto, temp_ipdst, temp_ipsrc
                global flag
                global count,sum,sum1,c1,c,FV,FD,AFR,FPS
                global t1,t2,t

                layer_2_arp = 0
                layer_2_llc = 0
                source_ip =0
                destination_ip =0
                layer_3_eapol = 0        
                layer_3_ip = 0
                layer_3_icmp = 0
                layer_3_icmp6 = 0

                layer_4_tcp = 0
                layer_4_udp = 0
                layer_4_tcp_ws=0
                
                layer_7_http = 0
                layer_7_https = 0
                layer_7_dhcp = 0
                layer_7_bootp = 0
                layer_7_ssdp = 0
                layer_7_dns = 0
                layer_7_mdns = 0
                layer_7_ntp = 0

                ip_padding = 0
                ip_ralert = 0
                # ip_add_count=0

                port_class_src = 0
                port_class_dst = 0

                pck_size = 0
                pck_rawdata = 0
                entropy=0
                time_sec = 0

                
                # Caputing packet length
                try:
                    pck_size=pkt.len
                except: pass


                # Print source port and destination port

                try:
                    if pkt[IP]:
                        # print("It has IP")
                        layer_3_ip = 1
                        temp=str(pkt[IP].show)
                        if "ICMPv6" in temp:
                            layer_3_icmp6 = 1
                        
                    temp=str(pkt[IP].dst)
                    source_ip = str(pkt[IP].src)
                    destination_ip = str(pkt[IP].dst)
                    
                    
                    if temp not in dst_ip_list:
                        ip_add_count=ip_add_count+1
                        dst_ip_list.append(temp)

                    # Getting source ip and destination ip
                    # print("Source Port: ",pkt[IP].sport)
                    port_class_src = port_class(pkt[IP].sport)
                    port_class_dst = port_class(pkt[IP].dport)
                except: pass

                try:
                    if pkt[IP].ihl >5:
                        if IPOption_Router_Alert(j):
                            pad=str(IPOption_Router_Alert(j).show)
                            if "Padding" in pad:
                                ip_padding=1
                            ip_ralert = 1     
                except:pass 
                
                try:
                    if pkt[ICMP]:
                        layer_3_icmp = 1  
                except:pass 
                
                try: 
                    if pkt[Raw]:
                        pck_rawdata = 1   
                except:pass 
                
                
                try:
                    if pkt[UDP]:
                        layer_4_udp = 1
                        if pkt[UDP].sport==68 or pkt[UDP].sport==67:
                            layer_7_dhcp = 1
                            layer_7_bootp = 1
                        if pkt[UDP].sport==53 or pkt[UDP].dport==53:
                            layer_7_dns = 1      
                        if pkt[UDP].sport==5353 or pkt[UDP].dport==5353:
                            layer_7_mdns = 1                    
                        if pkt[UDP].sport==1900 or pkt[UDP].dport==1900:
                            layer_7_ssdp = 1                    
                        if pkt[UDP].sport==123 or pkt[UDP].dport==123:
                            layer_7_ntp = 1                    
                except:pass 
                        
                
                try:
                    if pkt[TCP]:
                        # print("It has tcp")
                        layer_4_tcp = 1
                        layer_4_tcp_ws=pkt[TCP].window
                        
                        x = port_class(pkt[TCP].sport) 
                        y = port_class(pkt[TCP].dport)

                        if port_class_src==0 and x!=0:
                            port_class_src=x

                        if port_class_dst==0 and y!=0:
                            port_class_dst=y


                        if pkt[TCP].sport==80 or pkt[TCP].dport==80:
                            layer_7_http = 1      
                        if pkt[TCP].sport==443 or pkt[TCP].dport==443:
                            layer_7_https = 1  

                except:pass     


                try:
                    if pkt[TCP] and pkt[IP]:
                        # print("Entered")
                        c= len(pkt)
                        t1 = pkt.time%60
                        c1 = len(pkt[TCP].payload)

                        # print(c,t1,c1)

                        if(pkt[IP].src!=temp_ipsrc or pkt[IP].dst!=temp_ipdst or pkt[TCP].sport!= temp_sport or pkt[TCP].dport!=temp_dport or pkt[IP].proto!=temp_proto):
                                flag=1   

                        if(flag==1):
                            sum = c
                            sum1 = c1
                            t=t1
                            count=1
                        else:
                            sum=sum +c
                            sum1=sum1+c1
                            t2=pkt.time%60
                            t=t+t1
                            count=count+1
                    
                        temp_ipsrc, temp_ipdst, temp_sport, temp_dport, temp_proto = pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport, pkt[IP].proto

                        FV= sum
                        FPS = sum1
                        FD = t
                        AFR= (FV/FD)

                except: 
                    pass
                
                try:
                    if pkt[ARP]:
                        layer_2_arp = 1                                 
                except:pass 
                                
                
                try:
                    if pkt[LLC]:
                        layer_2_llc = 1                                 
                except:pass 
                                
                
                
                try:
                    if pkt[EAPOL]:
                        layer_3_eapol = 1                                 
                except:pass 
                    
                try:
                    entropy=pre_entropy(pkt[Raw].original)
                    # print("Entropy: ",entropy)
                except:pass

                if source_ip=='192.168.29.8' and destination_ip=='192.168.29.55':
                    print("Writing to csv file")
                    time_sec = pkt.time - start_timestamp
                    csv_writer.writerow([source_ip,time_sec,layer_2_arp,layer_2_llc,layer_3_eapol,layer_3_ip,layer_3_icmp,layer_3_icmp6,layer_4_tcp,layer_4_udp,layer_4_tcp_ws,layer_7_http,layer_7_https,layer_7_dhcp,layer_7_bootp,layer_7_ssdp,layer_7_dns,layer_7_mdns,layer_7_ntp,ip_padding,ip_ralert,port_class_src,port_class_dst,pck_size,pck_rawdata,entropy,FV,FPS,FD,AFR])
                    csv_file.flush()


                self.packet_received.emit(pkt)  
            sniff(prn=packet_feature_extractor)



class MyWindow(QWidget):
    def __init__(self):
        super().__init__()

        # Set up the layout
        layout = QVBoxLayout()

        # First Section - Collect Data
        self.collect_data_button = QPushButton('Collect Data', self)
        self.collect_data_button.clicked.connect(self.collect_data_function)
        layout.addWidget(self.collect_data_button)

        # Second Section - Calibrate Model to Network
        self.calibrate_button = QPushButton('Calibrate Model to Network', self)
        self.calibrate_button.clicked.connect(self.calibrate_function)
        layout.addWidget(self.calibrate_button)

        # Third Section - Live Prediction
        self.live_predict_button = QPushButton('Live Prediction', self)
        self.live_predict_button.clicked.connect(self.live_predict_function)
        layout.addWidget(self.live_predict_button)

        self.setLayout(layout)
        self.setWindowTitle('PyQt5 Example')

        self.packet_capture_thread = PacketCaptureThread()
        self.packet_capture_thread.packet_received.connect(self.handle_packet_received)


    def collect_data_function(self):
        self.calibrate_button.setEnabled(False)
        self.live_predict_button.setEnabled(False)
        self.collect_data_button.setEnabled(False)
        self.collect_data_button.setText("Collecting Data...")
        self.packet_capture_thread.start()

    def handle_packet_received(self, pkt):
        print("Packet Received:", pkt.summary())

    def calibrate_function(self):
        self.collect_data_button.setEnabled(False)
        self.calibrate_button.setEnabled(False)
        self.calibrate_button.setText("Calibrating...")
        self.live_predict_button.setEnabled(False)
        print("Calibrating...")
        
        self.collect_data_button.setEnabled(True)
        self.calibrate_button.setEnabled(True)
        self.calibrate_button.setText("Calibrate Model to Network")
        self.live_predict_button.setEnabled(True)



    def live_predict_function(self):
        self.collect_data_button.setEnabled(False)
        self.calibrate_button.setEnabled(False)
        self.live_predict_button.setEnabled(False)
        self.live_predict_button.setText("Live Predicting...")
        print("Live Predicting...")
        self.collect_data_button.setEnabled(True)
        self.calibrate_button.setEnabled(True)
        self.live_predict_button.setEnabled(True)
        self.live_predict_button.setText("Live Prediction")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MyWindow()
    window.show()
    sys.exit(app.exec_())
