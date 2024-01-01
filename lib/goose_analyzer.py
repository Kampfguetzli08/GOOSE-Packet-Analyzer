def analyze_goose_packets(igpks):

    results = dict()

    for ied in igpks:

        results[ied] = {
            'id': ied,
            'src': igpks[ied]['src'],
            'dst': igpks[ied]['dst'],
            'gptype': dict()
        }

        for gpid in igpks[ied]['gptype']:

            results[ied]['gptype'][gpid] = {
                'gocbref': igpks[ied]['gptype'][gpid]['gocbref'],
                'datset': igpks[ied]['gptype'][gpid]['datset'],
                'goid': igpks[ied]['gptype'][gpid]['goid'],
                'packets': len(igpks[ied]['gptype'][gpid]['packets'])
            }


            prev_pkt = {
                'pktnr': 0,
            }

            warnings = list()

            for packet in igpks[ied]['gptype'][gpid]['packets']:
                if prev_pkt['pktnr'] == 0:
                    prev_pkt = {
                        'stnum': packet['stnum'],
                        'sqnum': packet['sqnum'],
                        'pktnr': packet['pktnr']
                    }
                    continue

                if packet['stnum'] == prev_pkt['stnum']:
                    # expected packet
                    if packet['sqnum'] == prev_pkt['sqnum'] + 1:
                        pass

                    else:
                        warnings.append(
                            'sqNum (%i) is out of order (expected %i) between packets %i and %i' %
                            (packet['sqnum'], prev_pkt['sqnum'] + 1, prev_pkt['pktnr'], packet['pktnr'])
                        )

                elif packet['stnum'] == prev_pkt['stnum'] + 1:
                    if packet['sqnum'] == 0:
                        warnings.append(
                            'Event occurred at packet %i' % (packet['pktnr'])
                        )
                    else:
                        warnings.append(
                            'sqNum (%i) is out of order (expected %i) between packets %i and %i' %
                            (packet['sqnum'], 0, prev_pkt['pktnr'], packet['pktnr'])
                        )

                else:
                    warnings.append(
                        'stNum %i is out of order (expected %i or %i) at packet %i' %
                        (packet['stnum'], prev_pkt['stnum'], prev_pkt['stnum'] + 1, packet['pktnr'])
                    )

                prev_pkt['stnum'] = packet['stnum']
                prev_pkt['sqnum'] = packet['sqnum']
                prev_pkt['pktnr'] = packet['pktnr']

            results[ied]['gptype'][gpid]['warnings'] = warnings.copy()

    return results
