from scapy.all import*
import math
import os

def find_the_way(path,file_format):
    files_add = []
    for r, d, f in os.walk(path):
        for file in f:
            if file_format in file:
                files_add.append(os.path.join(r, file))  
    return files_add


def folder(f_name):
    try:
        if not os.path.exists(f_name):
            os.makedirs(f_name)
    except OSError:
        print ("The folder could not be created!")


def port_class(port):
    if 0 <= port <= 1023:
        return 1
    elif  1024 <= port <= 49151 :
        return 2
    elif 49152 <=port <= 65535 :
        return 3
    else:
        return 0

def pre_entropy(payload):
    characters=[]
    for i in payload:
        characters.append(i)
    return shannon(characters)

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



files_add=find_the_way('./pcaps/','.pcap')
folder_name="./csvs/"
folder(folder_name)


count=0
for i in files_add:
    pkt = rdpcap(i)
    print("\n\n"+"====================="+ i[8:]+"====================="+"\n" )
    csvname=str(i)
    csvname=csvname[8:-5]
    csvname=csvname.replace("\\","@")
    label=csvname
    where_is_at=label.find("@")
    label=label[0:where_is_at]
    
    ths = open(folder_name+csvname+".csv", "w")    

    
    

    ip_add_count = 0    #
    dst_ip_list=[]
    
    
    
    for j in pkt:
        count=count+1
        print(pkt)
        print(j)
        
        layer_2_arp = 0
        layer_2_llc = 0
        
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


        port_class_src = 0
        port_class_dst = 0

        pck_size = 0
        pck_rawdata = 0
        entropy=0
        
        try:
            pck_size=j.len
        except:pass
    
        try:
            if j[IP]:
                layer_3_ip = 1
                temp=str(j[IP].show)
                if "ICMPv6" in temp:
                    layer_3_icmp6 = 1
                    
            temp=str(j[IP].dst)
            if temp not in dst_ip_list:
                ip_add_count=ip_add_count+1
                dst_ip_list.append(temp)
            port_class_src = port_class(j[IP].sport)
            port_class_dst = port_class(j[IP].dport)
                
        except:pass 
        
        
    
        try:
            if j[IP].ihl >5:
                if IPOption_Router_Alert(j):
                    pad=str(IPOption_Router_Alert(j).show)
                    if "Padding" in pad:
                        ip_padding=1
                    ip_ralert = 1     
        except:pass 
        
        try:
            if j[ICMP]:
                layer_3_icmp = 1  
        except:pass 
        
        try:
            if j[Raw]:
                pck_rawdata = 1   
        except:pass 
        
        
        try:
            if j[UDP]:
                layer_4_udp = 1
                if j[UDP].sport==68 or j[UDP].sport==67:
                    layer_7_dhcp = 1
                    layer_7_bootp = 1
                if j[UDP].sport==53 or j[UDP].dport==53:
                    layer_7_dns = 1      
                if j[UDP].sport==5353 or j[UDP].dport==5353:
                    layer_7_mdns = 1                    
                if j[UDP].sport==1900 or j[UDP].dport==1900:
                    layer_7_ssdp = 1                    
                if j[UDP].sport==123 or j[UDP].dport==123:
                    layer_7_ntp = 1                    
        except:pass 
                
        
        try:
            if j[TCP]:

                layer_4_tcp = 1
                layer_4_tcp_ws=j[TCP].window
                if j[TCP].sport==80 or j[TCP].dport==80:
                    layer_7_http = 1      
                if j[TCP].sport==443 or j[TCP].dport==443:
                    layer_7_https = 1  
        except:pass        
        
        try:
            if j[ARP]:
                layer_2_arp = 1                                 
        except:pass 
                        
        
        try:
            if j[LLC]:
                layer_2_llc = 1                                 
        except:pass 
                        
        
        
        try:
            if j[EAPOL]:
                layer_3_eapol = 1                                 
        except:pass 
            
        try:
            entropy=pre_entropy(j[Raw].original)
        except:pass
        line=[layer_2_arp, layer_2_llc, layer_3_eapol, layer_3_ip, layer_3_icmp, layer_3_icmp6, layer_4_tcp, layer_4_udp, layer_4_tcp_ws, layer_7_http, layer_7_https, layer_7_dhcp, layer_7_bootp, layer_7_ssdp, layer_7_dns, layer_7_mdns, layer_7_ntp, ip_padding, ip_add_count, ip_ralert, port_class_src, port_class_dst, pck_size, pck_rawdata,entropy, label]  
        line=str(line).replace("[","")
        line=str(line).replace("]","")
        line=str(line).replace("\'","")
        ths.write(str(line)+"\n")  
    ths.close()          


files_add=find_the_way('./csvs/','.csv')


features_name=['ARP',
    'LLC',
    'EAPOL',
    "IP",
    'ICMP',
    'ICMP6',
    'TCP',
    'UDP',
    'TCP_w_size',
    'HTTP',
    'HTTPS',
    'DHCP',
    'BOOTP',
    'SSDP',
    'DNS',
    'MDNS',
    'NTP',
    'IP_padding',
    'IP_add_count',
    'IP_ralert',
    'Portcl_src',
    'Portcl_dst',
    'Pck_size',
    'Pck_rawdata',
    "Entropy",
    'Label']             
   
features_name=( ",".join( i for i in features_name ) )
devices=[]
flag=False
name="hybrid.csv"
ths = open(name, "w") 
for i in files_add:
    temp=i
    where_is_at=temp.find("@")
    temp=i[7:where_is_at]
    if temp in devices:
        name=temp+"_all.csv"
        ths = open(name, "a") 
        with open(i, "r") as file:
            while True:   
                line=file.readline()
                if line=="":
                    break
                else:
                    line=line
                    ths.write(str(line))
    else:
        devices.append(temp)
        if flag:
            ths.close()
        name=temp+"_all.csv"
        ths = open(name, "w") 
        ths.write(features_name)
        with open(i, "r") as file:
            while True:   
                line=file.readline()
                if line=="":
                    break
                else:
                    line=line
                    ths.write(str(line))
        flag=True 
ths.close()        

name="hybrid.csv"
ths = open(name, "w") 
ths.write(features_name+"\n")
for i in files_add:
    with open(i, "r") as file:
        while True:   
            line=file.readline()
            if line=="":
                break
            else:
                line=line
                ths.write(str(line))
ths.close()

