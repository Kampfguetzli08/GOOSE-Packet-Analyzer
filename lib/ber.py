import struct
from lib.goose_asn import *

class DecoderError(Exception):
    pass


def decode_data(data, tagmap, ignore_errors=True):
    results = list()
    alldata = Data()

    while len(data) > 0:
        chunk = 1
        tag = ord(data[:chunk])
        data = data[chunk:]
        tag_class = tag & 0xC0
        tag_format = tag & 0x20
        tag_id = tag & 0x1F

        length = ord(data[:chunk])
        data = data[chunk:]

        # length field is longer than a byte
        if length & 0x80 == 0x80:
            n = length & 0x7F
            length = unpack_varint(data[:n], n)
            data = data[n:]


        if tag == 161 or tag == 162:
            results.append(decode_data(data[:length], alldata.tagmap))
            data = data[length:]
        else:
            # decoding the bytes
            try:
                name = tagmap[(tag_class, tag_format, tag_id)][0]
                inst = tagmap[(tag_class, tag_format, tag_id)][1]
                val = inst(data[:length], length)
                #val.tag(tag_class, tag_format, tag_id)
            except KeyError:
                if ignore_errors:
                    print(f'Unfound AllData tag ({tag_class}, {tag_format}, {tag_id}) raw_bytes: {data[:length]}')
                    continue
                else:
                    raise DecoderError('Tag not found in tagmap')
            finally:
                data = data[length:]

            results.append(val)

    return results

def decoder(data, tagmap, ignore_errors=True):

    results = dict()
    alldata = Data()

    while len(data) > 0:
        chunk = 1
        tag = ord(data[:chunk])
        data = data[chunk:]
        tag_class = tag & 0xC0
        tag_format = tag & 0x20
        tag_id = tag & 0x1F

        length = ord(data[:chunk])
        data = data[chunk:]
        # length field is longer than a byte
        if length & 0x80 == 0x80:
            n = length & 0x7F
            length = unpack_uvarint(data[:n], n)
            data = data[n:]

        # decoding the bytes
        try:
            name = tagmap[(tag_class, tag_format, tag_id)][0]
            inst = tagmap[(tag_class, tag_format, tag_id)][1]
            # 171 is in HEX 0xAB for the AllData Tag
            if tag == 171:
                val = decode_data(data[:length], alldata.tagmap)
            else:
                val = inst(data[:length], length)
            #val.tag(tag_class, tag_format, tag_id)
        except KeyError:
            if ignore_errors:
                print(f'Unfound tag ({tag_class}, {tag_format}, {tag_id}) raw_bytes: {data}')
                continue
            else:
                raise DecoderError('Tag not found in tagmap')
        finally:
            data = data[length:]

        results[name] = val

    return results


