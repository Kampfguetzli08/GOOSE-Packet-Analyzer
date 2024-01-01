import argparse
from scapy.all import *
from lib.goose_filter import *
from lib.goose_analyzer import *
from lib.generate_report import *
import time

def readpcap(filepath):
    pcap = rdpcap(filepath)
    return filter_goose_packets(pcap)


def main():
    parser = argparse.ArgumentParser(
        description='Analyzes a pcap file and checks if there are any GOOSE attacks/anomalies')
    parser.add_argument(
        '-f',
        '--file',
        help='Path to pcap file',
        required=True,
        type=str,
    )

    args = parser.parse_args()

    gps = readpcap(args.file)

    results = analyze_goose_packets(gps)

    report = generate_report(results)

    with open('report.html', 'w') as rf:
        rf.write(report)


if __name__ == '__main__':
    main()
