import datetime

from scapy.all import *
from pyasn1.codec.ber import decoder
from pyasn1.codec.ber import encoder
from pyasn1.type import tag
from lib.goose import GOOSE, GOOSEPDU
from lib.goose_pdu import AllData, Data, IECGoosePDU, UtcTime
from pyasn1 import debug

def packet_is_goose(pkt):
    # hex code for GOOSE packet type
    ETHER_TYPE = 0x88b8

    is_goose = False

    # packet with vlan
    if pkt.haslayer('Dot1Q'):
        if pkt['Dot1Q'].type == ETHER_TYPE:
            is_goose = True
    # 'normal' ethernet packet
    if pkt.haslayer('Ether'):
        if pkt['Ether'].type == ETHER_TYPE:
            is_goose = True

    return is_goose


def gpdu_decoder(encoded_data):
    debug.setLogger(debug.Debug('all'))

    g = IECGoosePDU().subtype(
        implicitTag=tag.Tag(
            tag.tagClassApplication,
            tag.tagFormatConstructed,
            1
        )
    )
    decoded_data, unprocessed_trail = decoder.decode(
        encoded_data,
        asn1Spec=g
    )
    # This should work, but not sure.
    return decoded_data


def extract_packet_information(packet, goose_decoded, pktnr):

    # extract seconds from timestamp and convert it
    tstr = str(datetime.datetime.fromtimestamp(
                    int.from_bytes(
                        bytearray(goose_decoded['t'])[:4], 'big'), tz=datetime.timezone.utc
                    ).strftime('%Y-%m-%d %H:%M:%S')
               )

    # extract and calculate nanoseconds from timestamp
    tns = str(int.from_bytes(
            bytearray(goose_decoded['t'])[4:7], 'big') / (2 ** 24))[1:11]

    goose_dict = {
        'pktnr': pktnr,
        'src': packet.src,
        'dst': packet.dst,
        'gocbref': str(goose_decoded['gocbRef']),
        'tatl': int(goose_decoded['timeAllowedtoLive']),
        'datset': str(goose_decoded['datSet']),
        'goid': str(goose_decoded['goID']),
        'ts': tstr + tns,
        'tsraw': int.from_bytes(bytearray(goose_decoded['t']), 'big'),
        'stnum': int(goose_decoded['stNum']),
        'sqnum': int(goose_decoded['sqNum']),
        'simulation': bool(goose_decoded['simulation']),
        'confrev': int(goose_decoded['confRev']),
        'ndscom': bool(goose_decoded['ndsCom']),
        'ndse': int(goose_decoded['numDatSetEntries']),
        'data': goose_decoded['allData'],
    }

    return goose_dict


def filter_goose_packets(pcap):
    goose_packets = dict()
    pktnr = 1

    for pkt in pcap:
        print(pktnr)
        if packet_is_goose(pkt):
            gpkt = GOOSE(pkt.load)
            gpdu = gpkt[GOOSEPDU].original

            # decoded goose pdu
            gd = gpdu_decoder(gpdu)

            ied_identifier = pkt.src.replace(':', '') + '_' + pkt.dst.replace(':', '')
            if ied_identifier not in goose_packets:
                goose_packets[ied_identifier] = list()

            goose_packets[ied_identifier].append(extract_packet_information(pkt, gd, pktnr).copy())

        pktnr += 1

    return goose_packets




