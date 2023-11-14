from scapy.all import*
from scapy.layers.http import HTTPRequest
import math
import csv
import numpy as np
from sklearn import preprocessing
import requests
import json

url = "http://localhost:8601/v1/models/iot_model:predict"
headers = {"content-type": "application/json"}


ip = ['192.168.29.8']
label = ['Water_Sensor']

ip_hashmap = {}
for i in range(len(ip)):
    ip_hashmap[ip[i]] = label[i]


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

with open('predictor2.csv', 'w', newline='') as csv_file:
    features_name=['Arrival Time','ARP','LLC','EAPOL',"IP",'ICMP','ICMP6','TCP','UDP','TCP_w_size','HTTP','HTTPS','DHCP','BOOTP','SSDP','DNS','MDNS','NTP','FTP','IP_padding','IP_ralert','Portcl_src','Portcl_dst','Pck_size','Pck_rawdata',"Entropy","Flow Volume","Flow Per Second","Flow Duration","Average Flow Rate","Label"] 
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow(features_name)
    print("CSV file created and headers written")

    def shannon(data):
        '''
        The network entropy is a disorder measure derived from information theory to describe the level of randomness and the amount of information encoded in a graph.
        It is a https://scapy.readthedocs.io/en/latest/_images/isakmp_dump.pngrelevant metric to quantitatively characterize real complex networks and can also be used to quantify network complexity.
        '''
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
        '''
        This function extracts the features from the packet and writes it to the csv file.
        Features are extracted from the packet using scapy library.
        '''
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
        layer_7_ftp = 0

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
                if pkt[TCP].dport==21 or pkt[TCP].sport==21:
                    layer_7_ftp = 1

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


        # if source_ip=='192.168.29.55':
        #     print(destination_ip)

        # print(source_ip,layer_2_arp,layer_2_llc,layer_3_eapol,layer_3_ip,layer_3_icmp,layer_3_icmp6,layer_4_tcp,layer_4_udp,layer_4_tcp_ws,layer_7_http,layer_7_https,layer_7_dhcp,layer_7_bootp,layer_7_ssdp,layer_7_dns,layer_7_mdns,layer_7_ntp,ip_padding,ip_ralert,port_class_src,port_class_dst,pck_size,pck_rawdata,entropy)
        
        if HTTPRequest in pkt:
            # source_ip = str(pkt[IP].sr/
            layer_7_http = 1
  

        # try:
        #     if pkt[ARP]:
        #         # print("ARP")
        # except Exception as e:
        #     pass

        
        if source_ip in ip_hashmap:
            label  = ip_hashmap[source_ip]


            time_sec = pkt.time - start_timestamp
        # new_data = np.array([time_sec,layer_2_arp,layer_2_llc,layer_3_eapol,layer_3_ip,layer_3_icmp,layer_3_icmp6,layer_4_tcp,layer_4_udp,layer_4_tcp_ws,layer_7_http,layer_7_https,layer_7_dhcp,layer_7_bootp,layer_7_ssdp,layer_7_dns,layer_7_mdns,layer_7_ntp,layer_7_ftp,ip_padding,ip_ralert,port_class_src,port_class_dst,pck_size,pck_rawdata,entropy,FV,FPS,FD,AFR,label])
        # print(new_data)

            input_data_np = np.array([layer_2_arp,layer_2_llc,layer_3_eapol,layer_3_ip,layer_3_icmp,layer_3_icmp6,layer_4_tcp,layer_4_udp,layer_4_tcp_ws,layer_7_http,layer_7_https,layer_7_dhcp,layer_7_bootp,layer_7_ssdp,layer_7_dns,layer_7_mdns,layer_7_ntp,layer_7_ftp,ip_padding,ip_ralert,port_class_src,port_class_dst,pck_size,pck_rawdata])
            input_data_np = input_data_np.reshape(1, -1)
            input_data = {"instances": input_data_np.tolist()}
            json_data = json.dumps(input_data)
            response = requests.post(url, data=json_data, headers=headers)
            y = response.json()
            for key, value in y.items():
                res = np.array(value).argmax()
                if layer_4_udp==1:
                    print(res)
                    print(value)
            # y = response.json().predictions[0]
            # print(y.argmax())
        # else:
            # print("IP not accepted")

        # csv_writer.writerow(new_data)

            # csv_writer.flush()

    capture = sniff(prn=packet_feature_extractor)
