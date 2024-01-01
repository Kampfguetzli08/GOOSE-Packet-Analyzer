import datetime

from scapy.all import *
from lib.goose_asn import GOOSE, GOOSEPDU
from lib.ber import *


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


def extract_packet_information(goose_decoded, pktnr):

    goose_dict = {
        'pktnr': pktnr,
        'tatl': goose_decoded['timeAllowedToLive'].data,
        'ts': goose_decoded['t'].data,
        'stnum': goose_decoded['stNum'].data,
        'sqnum': goose_decoded['sqNum'].data,
        'test': goose_decoded['test'].data,
        'confrev': goose_decoded['confRev'].data,
        'ndscom': goose_decoded['ndsCom'].data,
        'ndse': goose_decoded['numDataSetEntries'].data,
        'data': goose_decoded['allData'],
    }

    return goose_dict


def filter_goose_packets(pcap):
    goose_packets = dict()
    pktnr = 1

    for pkt in pcap:
        # print(pktnr)
        if packet_is_goose(pkt):
            gpkt = GOOSE(pkt.load)
            gpdu_raw = gpkt.load

            # if the value of the second byte is smaller than 0x80 shift 2 bytes
            # if it's bigger, shift it for 3 or more bytes depending on the and-operation
            if gpdu_raw[1] < 0x80:
                byteshift = 2
            else:
                byteshift = (gpdu_raw[1] & 0x7F) + 2

            gd = decoder(gpdu_raw[byteshift:], GOOSEPDU.tagmap)

            ied_id = pkt.src.replace(':', '') + '_' + pkt.dst.replace(':', '')
            if ied_id not in goose_packets:
                goose_packets[ied_id] = dict()
                goose_packets[ied_id] = {
                    'src': pkt.src,
                    'dst': pkt.dst,
                    'gptype': dict()
                }

            gpid = str(gd['gocbRef']) + str(gd['datSet']) + str(gd['goID'])
            if gpid not in goose_packets[ied_id]['gptype']:
                goose_packets[ied_id]['gptype'][gpid] = {
                    'gocbref': str(gd['gocbRef']),
                    'datset': str(gd['datSet']),
                    'goid': str(gd['goID']),
                    'packets': list()
                }

            goose_packets[ied_id]['gptype'][gpid]['packets'].append(extract_packet_information(gd, pktnr))

        pktnr += 1

    return goose_packets




