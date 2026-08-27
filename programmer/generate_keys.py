# generate_keys.py
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import os

os.makedirs("keys", exist_ok=True)

def generate_and_save(prefix):
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(f"keys/{prefix}_private.pem", "wb") as f:
        f.write(priv_pem)
    with open(f"keys/{prefix}_public.pem", "wb") as f:
        f.write(pub_pem)

    print(f"{prefix} key pair generated.")

generate_and_save("device")
generate_and_save("programmer")