import hmac
import hashlib
from hashlib import pbkdf2_hmac
from binascii import a2b_hex, b2a_hex


def compute_pmk(passphrase: str, ssid: bytes) -> bytes:
    """
    Derive the Pairwise Master Key (PMK) using PBKDF2-HMAC-SHA1
    """
    return pbkdf2_hmac('sha1', passphrase.encode(), ssid, 4096, 32)


def custom_prf512(key: bytes, A: bytes, B: bytes) -> bytes:
    """
    WPA2 PRF to derive the Pairwise Transient Key (PTK) from PMK
    """
    blen = 64
    i = 0
    R = b''
    while len(R) < blen:
        hmacsha1 = hmac.new(key, A + b'\x00' + B + bytes([i]), hashlib.sha1)
        R += hmacsha1.digest()
        i += 1
    return R[:blen]


def compute_ptk(pmk: bytes, ap_mac: bytes, client_mac: bytes, anonce: bytes, snonce: bytes) -> bytes:
    """
    Derive the Pairwise Transient Key (PTK)
    """
    # Ensure correct ordering: min-max of MAC and nonces
    mac1, mac2 = sorted([ap_mac, client_mac])
    nonce1, nonce2 = sorted([anonce, snonce])
    B = mac1 + mac2 + nonce1 + nonce2
    return custom_prf512(pmk, b"Pairwise key expansion", B)


def compute_mic(ptk: bytes, eapol_frame: bytes) -> bytes:
    """
    Compute the MIC using the first 16 bytes of PTK (KCK)
    """
    kck = ptk[0:16]
    mic = hmac.new(kck, eapol_frame, hashlib.sha1).digest()
    return hmac.new(kck, eapol_frame, hashlib.sha1).digest()[:16]




