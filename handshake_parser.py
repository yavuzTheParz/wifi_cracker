from scapy.all import rdpcap, Dot11, EAPOL, Dot11Elt

def parse_handshake(cap_path):
    packets = rdpcap(cap_path)  # Load packets from file
    ssid = None
    ap_mac = None
    client_mac = None
    eapol1 = None
    eapol2 = None

    eapol_frames = []

    for pkt in packets:
        if pkt.haslayer(Dot11):
            # SSID (only needs to be captured once)
            if ssid is None and pkt.type == 0 and pkt.subtype in [8, 5]:  # Beacon or Probe Response
                ssid_layer = pkt.getlayer(Dot11Elt)
                while ssid_layer:
                    if ssid_layer.ID == 0:  # SSID field
                        ssid = ssid_layer.info
                        break
                    ssid_layer = ssid_layer.payload.getlayer(Dot11Elt)

        # Collect EAPOL frames (part of handshake)
        if pkt.haslayer(EAPOL):
            eapol_frames.append(pkt)

    # Check if we found enough handshake messages
    if len(eapol_frames) < 2:
        raise Exception("Not enough EAPOL frames found in capture.")
        # Assign the first two EAPOL frames (assume in order for now)
    eapol1 = eapol_frames[0]
    eapol2 = eapol_frames[1]

    # MAC addresses
    ap_mac = bytes.fromhex(eapol1.addr2.replace(':', ''))
    client_mac = bytes.fromhex(eapol1.addr1.replace(':', ''))

    # Get raw EAPOL payloads (just the EAPOL part, not full 802.11)
    raw1 = bytes(eapol1.getlayer(EAPOL).original)
    raw2 = bytes(eapol2.getlayer(EAPOL).original)

    # Extract nonces and MIC
    anonce = raw1[13:45]     # 32 bytes starting at offset 13
    snonce = raw2[13:45]     # same offset for SNonce

    real_mic = raw2[77:93]   # 16-byte MIC at fixed offset

    # Zero out the MIC field in EAPOL frame
    eapol_frame = bytearray(raw2)
    eapol_frame[77:93] = b'\x00' * 16

    return {
        'ssid': ssid,
        'ap_mac': ap_mac,
        'client_mac': client_mac,
        'anonce': anonce,
        'snonce': snonce,
        'eapol_frame': bytes(eapol_frame),  # with MIC zeroed
        'real_mic': real_mic
    }

if __name__ == '__main__':
    result = parse_handshake('wpa.full.cap')
    for k, v in result.items():
        print(f"{k}: {v.hex() if isinstance(v, bytes) else v}")

