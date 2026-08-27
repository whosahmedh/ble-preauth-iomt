# sign_test.py
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

PROGRAMMER_ID = b"PROG0001"

def sign_challenge(nonce: bytes, private_key) -> bytes:
    """Sign (nonce || PROGRAMMER_ID) and return a raw 64-byte r||s signature,
    since PSA Crypto on the firmware side expects raw bytes, not the DER
    encoding this library produces by default."""
    message = nonce + PROGRAMMER_ID
    der_signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_signature)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")

if __name__ == "__main__":
    with open("keys/programmer_private.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    # A fixed, known nonce so the result is reproducible: 0x00, 0x01, ... 0x1f
    test_nonce = bytes(range(32))
    signature = sign_challenge(test_nonce, private_key)

    print(f"Message length: {len(test_nonce) + len(PROGRAMMER_ID)} bytes")
    print(f"Signature length: {len(signature)} bytes")
    print(f"Signature (hex): {signature.hex()}")
    print()
    print("C array for firmware test (Step 4.4):")
    print(", ".join(f"0x{b:02x}" for b in signature))