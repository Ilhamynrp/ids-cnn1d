def apply_rules(f):
    BRUTE_FORCE_PORTS = [21, 22, 23, 25, 445, 8080, 8000]

    # 1. RCE
    if (
        f['PayloadLen'] > 1400 and
        f['PayloadEntropy'] > 7.0 and
        f['Protocol_TCP'] == 1
    ):
        return 1.0, 'RCE'

    # 2. SQL Injection
    if (
        80 < f['PayloadLen'] < 1400 and
        4.2 < f['PayloadEntropy'] < 7.0 and
        f['Protocol_TCP'] == 1 and
        f['PacketRate'] <= 10   # Batasi untuk menghindari flood
    ):
        return 1.0, 'SQL Injection'


    # 3. Port Scan
    if (
        f['Flags_S'] == 1 and
        f['UniqueDports'] >= 2 and
        f['EntropyPorts'] >= 1.2 and
        f['PacketRate'] > 6 and
        f['PayloadLen'] < 100
    ):
        return 1.0, 'Port Scan'

    # 4. Brute Force
    if (
        f.get('DstPort', 0) in BRUTE_FORCE_PORTS and
        3 < f['PacketRate'] <= 40 and
        f['PayloadLen'] < 70 and
        f['PayloadEntropy'] < 4.2 and
        f['UniqueDports'] == 1 and
        f['Flags_S'] in [0, 1]
    ):
        return 1.0, 'Brute Force'

    # 5. SYN Flood
    if (
        f['Protocol_TCP'] == 1 and
        f['UniqueDports'] == 1 and
        f['PacketRate'] > 40 and
        f['PayloadLen'] < 80 and
        (f['Flags_S'] == 1 or f['SynBurst'] > 0)
        and f.get('DstPort', 0) not in BRUTE_FORCE_PORTS
    ):
        return 1.0, 'SYN Flood'

    return 0.0, 'Unknown'
