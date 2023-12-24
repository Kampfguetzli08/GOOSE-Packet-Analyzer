# GOOSE Packet Analyzer

Analyzes PCAP Files and detect GOOSE Anomalies

The PCAP files in the pcap folder are from this git repo https://github.com/smartgridadsc/IEC61850SecurityDataset/tree/master.
This includes the README.md in that folder as well.

## Function
This Script generates an HTML report for all GOOSE packets. 
![Part of an example report](report_example.png)
The report sorts the packets per IED (per source and destination mac address) and then per GOOSE Metadata (gocbRef, datSet and goID combined).
If it finds something suspicious it reports it under warnings. It also counts the total Packets per different GOOSE Metadata, which can also give hints that 
there are problems, especially if there are different counts per IED and GOOSE Metadata (this is seen in the example picture as there are 
3 packets more in Measurement compared to Alarm and Status).

## Usage
This project uses scapy. It's tested with python 3.12.0 and scapy 2.5.0, but should probably also work with newer versions.
```/bin/bash
python /path/to/main.py -f /path/to/pcap.pcap
```
