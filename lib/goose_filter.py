# from scapy.all import *
from pyasn1.codec.ber import decoder
from pyasn1.codec.ber import encoder
from pyasn1.type import tag

from lib.goose import GOOSE, GOOSEPDU
from lib.goose_pdu import AllData, Data, IECGoosePDU, UtcTime


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


def filter_goose_packets(pcap):
    pkt_dict = dict()

    for pkt in pcap:
        if packet_is_goose(pkt):
            gpkt = GOOSE(pkt.load)
            gpdu = gpkt[GOOSEPDU].original

            # decoded goose pdu
            gd = gpdu_decoder(gpdu)





