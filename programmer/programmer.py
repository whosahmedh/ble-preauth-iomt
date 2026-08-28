# programmer.py
import asyncio
from bumble.controller import Controller
from bumble.link import LocalLink
from bumble.host import Host
from bumble.device import Device, Peer
from bumble.transport import open_transport_or_link
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

PROGRAMMER_ID = b"PROG0001"

SERVICE_UUID       = "3b442fd2-ed4b-4606-ae27-07669ee14818"
CHALLENGE_UUID     = "fc3c0cf7-4ac7-4d50-9c75-93ed1dac7e72"
RESPONSE_UUID      = "1742473b-a085-4cbb-bd33-c04d014c7239"
AUTH_STATUS_UUID   = "29d9276d-30d5-451e-98b4-509ae3dbf70e"
SESSION_TOKEN_UUID = "5cf7b130-3f16-4cfa-b7a4-d40d852ebe64"


def sign_challenge(nonce: bytes, private_key) -> bytes:
    message = nonce + PROGRAMMER_ID
    der_signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_signature)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


async def main():
    with open("keys/programmer_private.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    link = LocalLink()
    print("[PROG] Connecting to Renode HCI bridge on port 3456...")
    hci_transport = await open_transport_or_link('tcp-client:127.0.0.1:3456')

    controller_a = Controller(
        'iomt-side', link=link,
        host_source=hci_transport.source, host_sink=hci_transport.sink
    )
    controller_b = Controller('programmer-side', link=link)
    host = Host()
    host.controller = controller_b
    device = Device(host=host)

    await device.power_on()
    print("[PROG] Scanning for the IoMT device...")

    found_address = None
    def on_advertisement(adv):
        nonlocal found_address
        if found_address is None:
            found_address = adv.address

    device.on('advertisement', on_advertisement)
    await device.start_scanning()
    for _ in range(50):
        if found_address:
            break
        await asyncio.sleep(0.1)
    await device.stop_scanning()

    if not found_address:
        print("[PROG] Never found the device -- is Renode running?")
        return

    print(f"[PROG] Connecting to {found_address}...")
    connection = await device.connect(found_address)
    peer = Peer(connection)
    await peer.request_mtu(247)
    
    services = await peer.discover_services()
    our_service = next((s for s in services if str(s.uuid).lower() == SERVICE_UUID), None)
    if not our_service:
        print("[PROG] Could not find our auth service!")
        await connection.disconnect()
        return

    characteristics = await our_service.discover_characteristics()
    chars = {str(c.uuid).lower(): c for c in characteristics}

    print("[PROG] Reading challenge (nonce)...")
    nonce = bytes(await peer.read_value(chars[CHALLENGE_UUID]))
    print(f"[PROG] Nonce received: {nonce.hex()}")

    signature = sign_challenge(nonce, private_key)
    print(f"[PROG] Signature generated ({len(signature)} bytes)")

    print("[PROG] Writing response (signature)...")
    await peer.write_value(chars[RESPONSE_UUID], signature, with_response=True)
    await asyncio.sleep(0.5)

    print("[PROG] Reading session token...")
    try:
        token = bytes(await peer.read_value(chars[SESSION_TOKEN_UUID]))
        print(f"[PROG] Session token: {token.hex()}")
    except Exception as e:
        print(f"[PROG] Could not read session token yet: {e}")

    print("[PROG] Initiating pairing...")
    try:
        await connection.pair()
        print("[PROG] Pairing complete!")
    except Exception as e:
        print(f"[PROG] Pairing failed or unsupported call: {e}")
    
    await asyncio.sleep(2)
    await connection.disconnect()
    print("[PROG] Disconnected.")

asyncio.run(main())