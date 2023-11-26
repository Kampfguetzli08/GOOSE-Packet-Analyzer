import argparse
from scapy.all import *
from lib.goose_filter import *
from lib.goose_analyzer import *



def analyze_goose_packets(goose_packets):
    report = dict()

    for ied_identifier in goose_packets:
        warnings = analyze_stnum_sqnum(goose_packets[ied_identifier])

        if len(warnings) > 0:
            report[ied_identifier] = warnings

    print(report)

def readpcap(filepath):
    pcap = rdpcap(filepath)
    return filter_goose_packets(pcap)


def main():
    parser = argparse.ArgumentParser(description='Analyzes a pcap file and checks if there are any GOOSE attacks/anomalies')
    parser.add_argument(
        '-f',
        '--file',
        help='Path to pcap file',
        required=True,
        type=str,
    )

    args = parser.parse_args()

    gps = readpcap(args.file)

    analyze_goose_packets(gps)

if __name__ == '__main__':
    main()
