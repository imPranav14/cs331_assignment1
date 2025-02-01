# 🕵️ Packet Sniffer Analysis and Metrics Extraction

## 📌 Overview

This project involves modifying a functional packet sniffer to analyze network traffic and extract key metrics. It includes:

- Capturing and replaying network traffic using **tcpreplay**.
- Extracting various **network metrics** from `.pcap` files.
- Generating **visualizations** and **statistical data** from the captured packets.
- Measuring **network speed performance** under different configurations.

Part1: 

    - step 1: Compile and Run the Packet Sniffer using the below command
    - python3 packet_sniffer.py 

    - Step 2: Replay the Captured Packets
    - Use tcpreplay to replay the .pcap file using the below command
    - sudo tcpreplay -i lo0 -p 1500 7.pcap


Part2:

    -upload the 7.pcap file and run the part2.py file to obtain the results.
    -use the following command
    -python3 part2.py