import pyshark
import csv

cap = pyshark.FileCapture("test.pcapng")


with open('output.csv', 'w', newline='') as csv_file:
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow(['Timestamp', 'Source IP', 'Destination IP', 'Protocol', 'Length','Payload'])

    for packet in cap:
        try:
            timestamp = packet.sniff_time
            source_ip = packet.ip.src
            dest_ip = packet.ip.dst
            protocol = packet.transport_layer
            length = packet.length
            payload = packet.data.data

            # Write packet data to CSV
            csv_writer.writerow([timestamp, source_ip, dest_ip, protocol, length,payload])
        except AttributeError:
            # Some packets might not have the required attributes
            print("Error: Packet has no attribute")
            pass

print("Conversion complete.")

