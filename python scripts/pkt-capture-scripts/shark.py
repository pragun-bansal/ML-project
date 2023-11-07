import pyshark
import csv
capture = pyshark.LiveCapture(output_file='test3.pcapng')
capture.sniff(timeout=10)

from scapy.all import  * 
import base64 


with open('data.csv', 'a', newline='') as csv_file:
    csv_writer = csv.writer(csv_file)
    # csv_writer.writerow(['Timestamp', 'Source IP', 'Destination IP', 'Protocol', 'Length','Payload', 'Time to live'])
    csv_writer.writerow(['Timestamp', 'Source IP', 'Destination IP', 'Protocol', 'Length','Payload', 'Time to live','Checksum','udp_source_port','udp_destination_port','udp_length','udp_checksum','udp_stream','eth_source','eth_destination','eth_type'])
    boolt = True
    def print_callback(pkt):
        global boolt
        try:
            protocol = pkt.transport_layer
            # print(pkt)
            if(protocol == 'TCP'):
                
                if(pkt.ip.src=='192.168.29.88'):
                    print(pkt)
                
                # print("Pretty callback")
                # pkt.pretty_print()
                # print("\n\n\n\n\n\n\n\n")
                timestamp = pkt.sniff_time
                source_ip = pkt.ip.src
                dest_ip = pkt.ip.dst
                ttl = pkt.ip.ttl
                protocol = pkt.transport_layer
                length = pkt.length
                payload = pkt.data.data
                # epoch_time = pkt.sniff_timestamp
                # checksum
                checksum = pkt.ip.checksum
                # print(checksum)

                
                # eXTRACTING UDP LAYER  INFO
                
                # print("UDP STARTED")
                udp_source_port = pkt.udp.srcport
                # print(udp_source_port)
                udp_destination_port = pkt.udp.dstport
                # print(udp_destination_port)
                udp_length = pkt.udp.length
                # print(udp_length)
                udp_checksum = pkt.udp.checksum
                # print(udp_checksum)
                # UDP TIMESTAMP
                # udp_timestamp = pkt.udp.time
                # print(udp_timestamp)
                # UDP STREAM INFO
                udp_stream = pkt.udp.stream
                print(udp_stream)
                # print(udp_source_port,udp_destination_port,udp_length,udp_checksum,udp_stream)

                # eXTRACTING eth LAYER  INFO
                print("ETH STARTED")
                eth_source = pkt.eth.src
                # print(eth_source)
                eth_destination = pkt.eth.dst
                # print(eth_destination)
                eth_type = pkt.eth.type
                # print(eth_type)
                # print(eth_source,eth_destination,eth_type)
                
                csv_writer.writerow([timestamp, source_ip, dest_ip, protocol, length,payload,ttl,checksum,udp_source_port,udp_destination_port,udp_length,udp_checksum,udp_stream,eth_source,eth_destination,eth_type])
                csv_file.flush()

                # print("\n\n\n\n\n\n\n\n",pkt,"\n\n\n\n\n\n\n\n")
            

                
    
                # print("\n\n\n\n\n\n\n\n",pkt.frame_info,"\n\n\n\n\n\n\n\n")
                
                # csv_writer.writerow([timestamp, source_ip, dest_ip, protocol, length,payload,ttl])
                
                if(boolt):
                    # if DNSQR in pkt: 
                    #     if pkt[DNS].id == 0x1337: 
                            # decoded_data = base64.b64decode(str(pkt[DNS].an.rdata)) 
                    file = open("output.txt", "a")
                    file.write("Timestamp: "+str(timestamp)+"\n")
                    file.write("Packet info: "+str(pkt)+"\n")
                    print(pkt)
                    boolt = False
        except AttributeError:
            print("Error: Packet has no attribute")
            pass  

    capture.apply_on_packets(print_callback)

capture.close()

