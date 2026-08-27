# test_load_private_key.py
from cryptography.hazmat.primitives import serialization

with open("keys/programmer_private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

print("Private key loaded successfully.")
print("Curve:", private_key.curve.name)