import argparse
import json
from scapy.all import *
from lib.goose_filter import *
from lib.goose_analyzer import *


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

    results = json.dumps(analyze_goose_packets(gps))

    print(results)


if __name__ == '__main__':
    main()
