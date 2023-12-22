import struct
import binascii
from datetime import datetime, timezone

from scapy.all import *
from scapy.fields import XShortField, XByteField, ConditionalField


def unpack_varint(data, length):
    if length == 1:
        data = struct.unpack('!b', data)[0]
    elif length == 2:
        data = struct.unpack('!h', data)[0]
    elif length == 4:
        data = struct.unpack('!i', data)[0]
    else:
        data = -1
    return data


def unpack_uvarint(data, length):
    if length == 1:
        data = struct.unpack('!B', data)[0]
    elif length == 2:
        data = struct.unpack('!H', data)[0]
    elif length == 4:
        data = struct.unpack('!I', data)[0]
    else:
        data = -1
    return data


class ASNType(object):
    tag = ''

    def __init__(self, data='', length=0):
        pass

    def unpack(self, data):
        raise NotImplemented()

    def pack(self, data):
        raise NotImplemented()

    def __str__(self):
        return str(self.data)

    def __repr__(self):
        return str(self.data)


class Integer(ASNType):
    def __init__(self, data='', length=0):
        self.data = unpack_varint(data, length)

    def __repr__(self):
        return self.data


class VisibleString(ASNType):
    def __init__(self, data='', length=0):
        self.data = data.decode('utf-8')

    def __repr__(self):
        return "'" + self.data + "'"


class Boolean(ASNType):
    ID = 3

    def __init__(self, data='', length=0):
        self.data = struct.unpack('!b', data)[0]

    def __repr__(self):
        if self.data:
            return "True"
        else:
            return "False"


class UTCTime(ASNType):
    def __init__(self, data='', length=0):
        # extract seconds from timestamp and convert it
        tstr = str(datetime.fromtimestamp(
            int.from_bytes(
                bytearray(data)[:4], 'big'), tz=timezone.utc
        ).strftime('%Y-%m-%d %H:%M:%S')
                   )

        # extract and calculate nanoseconds from timestamp
        tns = str(int.from_bytes(
            bytearray(data)[4:7], 'big') / (2 ** 24))[1:11]

        self.data = tstr + tns


class UnsignedInteger(ASNType):
    def __init__(self, data='', length=0):
        self.data = unpack_uvarint(data, length)

    def __repr__(self):
        return self.data


class Float(ASNType):
    def __init__(self, data='', length=0):
        self.data = struct.unpack('!f', data[1:])[0]

    def __repr__(self):
        return self.data


class Real(Float):
    pass


class OctetString(ASNType):
    def __init__(self, data='', length=0):
        self.data = struct.unpack('!d', data)[0]

    def __repr__(self):
        return self.data


class BitString(ASNType):
    ID = 4

    def __init__(self, data='', length=0):
        self.data = [data[0], data[1:]]

    def __repr__(self):
        return self.data

class ObjectID(ASNType):
    pass


class BCD(ASNType):
    pass


class BooleanArray(ASNType):
    pass


class UTF8String(ASNType):
    pass


class Data(object):
    tag = ''
    tagmap = {(128, 0, 3): ('boolean', Boolean),
              (128, 0, 4): ('bitstring', BitString),
              (128, 0, 5): ('integer', Integer),
              (129, 0, 6): ('unsigned', UnsignedInteger),
              (128, 0, 7): ('float', Float),
              (128, 0, 8): ('real', Real),
              (128, 0, 9): ('octetstring', OctetString),
              (129, 0, 10): ('visiblestring', VisibleString),
              (128, 0, 12): ('binarytime', UTCTime),
              (128, 0, 13): ('bcd', BCD),
              (129, 0, 14): ('booleanarray', BooleanArray),
              (128, 0, 15): ('objID', ObjectID),
              (128, 0, 16): ('mMSString', UTF8String),
              (128, 0, 17): ('utcstring', UTCTime)}

    def __init__(self, data=None, length=0):
        self.tagmap[(128, 32, 1)] = ('array', Data)
        self.tagmap[(128, 32, 2)] = ('structure', Data)

    def __getitem__(self, index):
        return self.data[index]

    def __repr__(self):
        return repr(self.data)


class GOOSEPDU(Packet):

    tagmap = {(128, 0, 0): ('gocbRef', VisibleString),
              (128, 0, 1): ('timeAllowedToLive', Integer),
              (128, 0, 2): ('datSet', VisibleString),
              (128, 0, 3): ('goID', VisibleString),
              (128, 0, 4): ('t', UTCTime),
              (128, 0, 5): ('stNum', Integer),
              (128, 0, 6): ('sqNum', Integer),
              (128, 0, 7): ('test', Boolean),
              (128, 0, 8): ('confRev', Integer),
              (128, 0, 9): ('ndsCom', Boolean),
              (128, 0, 10): ('numDataSetEntries', Integer),
              (128, 32, 11): ('allData', Data)}

    def __init__(self, data=None, length=0):
        pass


class GOOSE(Packet):
    name = "GOOSE"
    fields_desc = [
        XShortField("appid", 0),
        XShortField("length", 8),
        XShortField("reserved1", 0),
        XShortField("reserved2", 0),
    ]

    def post_build(self, packet, payload):
        goose_pdu_length = len(packet) + len(payload)
        packet = packet[:2] + struct.pack('!H', goose_pdu_length) + packet[4:]
        return packet + payload


bind_layers(GOOSE, GOOSEPDU)
