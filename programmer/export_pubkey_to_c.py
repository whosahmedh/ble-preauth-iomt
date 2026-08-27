# export_pubkey_to_c.py
from cryptography.hazmat.primitives import serialization

with open("keys/programmer_public.pem", "rb") as f:
    pub_key = serialization.load_pem_public_key(f.read())

raw_bytes = pub_key.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint
)

print(f"Public key is {len(raw_bytes)} bytes")

with open("keys/programmer_public_raw.bin", "wb") as f:
    f.write(raw_bytes)

c_array = ", ".join(f"0x{b:02x}" for b in raw_bytes)

header = f"""#ifndef PROGRAMMER_PUBKEY_H
#define PROGRAMMER_PUBKEY_H

#include <stdint.h>

/* Programmer ECDSA P-256 public key, uncompressed point: 0x04 || X || Y */
static const uint8_t programmer_pubkey[{len(raw_bytes)}] = {{
    {c_array}
}};

#endif
"""

with open("../firmware/include/programmer_pubkey.h", "w") as f:
    f.write(header)

print("Written to firmware/include/programmer_pubkey.h")