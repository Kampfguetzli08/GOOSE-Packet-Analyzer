def analyze_stnum_sqnum(ied_goose_packets):
    prev_pkt = dict()

    warnings = list()

    for packet in ied_goose_packets:
        key = packet['gocbref'] + packet['datset'] + packet['goid']

        if key not in prev_pkt:
            prev_pkt[key] = dict()
            prev_pkt[key]['stnum'] = packet['stnum']
            prev_pkt[key]['sqnum'] = packet['sqnum']
            prev_pkt[key]['gocbref'] = packet['gocbref']
            prev_pkt[key]['datset'] = packet['datset']
            prev_pkt[key]['goid'] = packet['goid']
            prev_pkt[key]['tsraw'] = packet['tsraw']
            continue

        if packet['stnum'] == prev_pkt[key]['stnum']:
            # expected packet
            if packet['sqnum'] == prev_pkt[key]['sqnum'] + 1:
                pass

            elif packet['sqnum'] < prev_pkt[key]['sqnum']:
                # packet delay
                if packet['tsraw'] < prev_pkt[key]['tsraw']:
                    warnings.append(
                        generate_warning('Packet is out of order', packet)
                    )
                # attack
                else:
                    warnings.append(
                        generate_warning('sqNum out of order, probably packet injection', packet)
                    )

            elif packet['sqnum'] > prev_pkt[key]['sqnum'] + 1:
                warnings.append(
                    generate_warning('sqNum missing, probably packet loss', packet)
                )

            elif packet['sqnum'] == prev_pkt[key]['sqnum']:
                warnings.append(
                    generate_warning('Double sqNum detected, probably packet injection', packet)
                )

        elif packet['stnum'] == prev_pkt[key]['stnum'] + 1:
            warnings.append(
                generate_warning('Event occured', packet)
            )

        elif packet['stnum'] < prev_pkt[key]['stnum']:
            if packet['tsraw'] < prev_pkt[key]['tsraw']:
                warnings.append(
                    generate_warning('Packet is out of order', packet)
                )
            else:
                warnings.append(
                    generate_warning('stNum is out of order, probably packet injection', packet)
                )

        elif packet['stnum'] > prev_pkt[key]['stnum'] + 1:
            warnings.append(
                generate_warning('stNum out of order, probably packet injection', packet)
            )

        prev_pkt[key]['stnum'] = packet['stnum']
        prev_pkt[key]['sqnum'] = packet['sqnum']
        prev_pkt[key]['gocbref'] = packet['gocbref']
        prev_pkt[key]['datset'] = packet['datset']
        prev_pkt[key]['goid'] = packet['goid']
        prev_pkt[key]['tsraw'] = packet['tsraw']

    return warnings


def generate_warning(warning, packet):
    return {
        'problem': warning,
        'pkt_nr': packet['pktnr'],
        'stnum': packet['stnum'],
        'sqnum': packet['sqnum'],
        'gocbref': packet['gocbref'],
        'datset': packet['datset'],
        'goid': packet['goid'],
        'ts': packet['ts'],
    }
