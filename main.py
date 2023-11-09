import argparse
from scapy.all import *
from lib.goose_filter import *


def readpcap(filepath):
    pcap = scapy.rdpcap(filepath)
    filter_goose_pakets(pcap)


def main():
    parser = argparse.ArgumentParser(description='Analizes a pcap file and checks if there are any attacks/anomalies')
    parser.add_argument(
        '-f',
        '--file',
        help='Path to pcap file',
        required=True,
        type=str,
    )

    args = parser.parse_args()

    readpcap(args.file)


if __name__ == '__main__':
    main()
