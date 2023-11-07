import subprocess
import os
import time

# Set the network interface to capture packets from
interface = "eth0"

# Start capturing packets in an infinite loop
while True:
    timestamp = int(time.time())
    output_file = f"packet_{timestamp}.pcap"

    # Use tshark to capture packets and save them to the output file
    command = ["tshark", "-i", interface, "-w", output_file]
    subprocess.Popen(command)

    # Wait for a specified duration or user input to stop capturing
    input("Press Enter to stop capturing...")
    
    # Stop the tshark process by sending a SIGINT signal
    subprocess.call(["pkill", "-2", "tshark"])
