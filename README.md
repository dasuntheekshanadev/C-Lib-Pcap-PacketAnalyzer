# C-Lib-Pcap-PacketAnalyzer
A C program for capturing and analyzing network packets on Linux using the pcap library. It provides detailed packet information and extracts payload data, allowing users to gain insights into network traffic.🕵️‍♂️📊📡
Packet Capture and Analysis Tool
This is a simple C program that captures network packets using pcap and analyzes them to extract packet information and payload data. The program is designed to work on Linux.

Prerequisites
Before running this program, make sure you have the following dependencies installed on your Linux system:

libpcap: A library used to capture network packets.
To install libpcap, open your terminal and run the following command:

bash
Copy code
sudo apt-get install libpcap-dev
How to Compile
To compile the program, use the following command:

bash
Copy code
gcc -o packet_capture packet_capture.c -lpcap
How to Run
After compiling the program, you can run it with the following command:

bash
Copy code
./packet_capture
The program will start capturing packets from the first available network device and analyze them. It will save the packet hex output to hexValues.txt and the packet info in readable format to details.com.txt. Each captured packet will be appended to these files.

Note: The program will run indefinitely until you stop it manually (press Ctrl + C).

Output Files
hexValues.txt: This file contains the hex dump of each captured packet.

details.com.txt: This file contains detailed information about each packet, including Ethernet header details, source, and destination IP addresses, protocol, source, and destination port, and payload data in hexadecimal format.

How it Works
The program uses pcap library to capture packets from the network device specified by dev->name. For each packet, it calls the packetHandler function to process and analyze the packet. The packet information and payload data are then saved in the output files as described above.

Please ensure you have the necessary permissions to access network devices for packet capture.

Disclaimer: This program is intended for educational and informational purposes only. Please use it responsibly and ensure that you have appropriate authorization to capture network packets.

Feel free to explore, modify, and enhance the program as needed!
