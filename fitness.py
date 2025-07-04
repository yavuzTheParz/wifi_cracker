from crypto_utils import compute_pmk, compute_ptk, compute_mic


def hamming_similarity(a: bytes, b: bytes) -> int:
    """Returns number of matching bits (max 128 for 16-byte MICs)"""
    return sum(8 - bin(x ^ y).count('1') for x, y in zip(a, b))


def fitness(password: str, hs: dict) -> int:
    """
    Compute fitness of a password guess based on WPA2 handshake data.

    Args:
        password: Password guess (string)
        hs: Dictionary containing parsed handshake info:
            - ssid (bytes)
            - ap_mac (bytes)
            - client_mac (bytes)
            - anonce (bytes)
            - snonce (bytes)
            - eapol_frame (bytes)
            - real_mic (bytes)

    Returns:
        Fitness score (int, 0–128): higher = better match
    """
    try:
        pmk = compute_pmk(password, hs['ssid'])
        ptk = compute_ptk(pmk, hs['ap_mac'], hs['client_mac'], hs['anonce'], hs['snonce'])
        mic = compute_mic(ptk, hs['eapol_frame'])

        return hamming_similarity(mic, hs['real_mic'])

    except Exception:
        return 0

