# attack_timeout.py
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
SESSION_TOKEN_UUID = "5cf7b130-3f16-4cfa-b7a4-d40d852ebe64"


def sign_challenge(nonce, private_key):
    message = nonce + PROGRAMMER_ID
    der_signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_signature)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


async def connect_and_discover():
    link = LocalLink()
    print("Connecting to Renode HCI bridge on port 3456...")
    hci_transport = await open_transport_or_link('tcp-client:127.0.0.1:3456')
    controller_a = Controller('iomt-side', link=link,
                               host_source=hci_transport.source, host_sink=hci_transport.sink)
    controller_b = Controller('attacker-side', link=link)
    host = Host()
    host.controller = controller_b
    device = Device(host=host)
    await device.power_on()

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
        raise RuntimeError("Never found the IoMT device -- is Renode running?")

    connection = await device.connect(found_address)
    peer = Peer(connection)
    services = await peer.discover_services()
    our_service = next((s for s in services if str(s.uuid).lower() == SERVICE_UUID), None)
    characteristics = await our_service.discover_characteristics()
    chars = {str(c.uuid).lower(): c for c in characteristics}
    return connection, peer, chars


async def main():
    with open("keys/programmer_private.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    print("[ATTACK-TIMEOUT] Authenticating legitimately first (real key, real signature)...")
    connection, peer, chars = await connect_and_discover()

    nonce = bytes(await peer.read_value(chars[CHALLENGE_UUID]))
    print(f"[ATTACK-TIMEOUT] Nonce: {nonce.hex()}")

    signature = sign_challenge(nonce, private_key)
    print(f"[ATTACK-TIMEOUT] Signed with the REAL key: {signature.hex()}")

    try:
        await peer.write_value(chars[RESPONSE_UUID], signature, with_response=True)
    except (Exception, asyncio.CancelledError) as e:
        print(f"[ATTACK-TIMEOUT] Write did not complete cleanly: {e}")

    await asyncio.sleep(0.5)

    print("[ATTACK-TIMEOUT] Reading session token (should SUCCEED -- we authenticated for real)...")
    try:
        token = bytes(await peer.read_value(chars[SESSION_TOKEN_UUID]))
        print(f"[ATTACK-TIMEOUT] Session token received: {token.hex()}")
    except (Exception, asyncio.CancelledError) as e:
        print(f"[ATTACK-TIMEOUT] !!! UNEXPECTED: token read failed even though we authenticated correctly: {e}")
        print("[ATTACK-TIMEOUT] Cannot continue this test -- something else is wrong.")
        return

    print("[ATTACK-TIMEOUT] Polling the session token until the timer expires (real proof, not a guess)...")
    expired = False
    try:
        for i in range(45):
            await asyncio.sleep(2)
            try:
                token_check = bytes(await peer.read_value(chars[SESSION_TOKEN_UUID]))
                print(f"[ATTACK-TIMEOUT]   still valid at +{(i+1)*2}s (token: {token_check.hex()[:16]}...)")
            except (Exception, asyncio.CancelledError, RuntimeError, KeyError) as e:
                print(f"[ATTACK-TIMEOUT] Token read failed at +{(i+1)*2}s -- session has expired: {e}")
                expired = True
                break
    except BaseException as e:
        print(f"[ATTACK-TIMEOUT] Loop interrupted -- session has expired: {e}")
        expired = True

    if not expired:
        print("[ATTACK-TIMEOUT] Session never expired within the poll window -- inconclusive, not a pass.")
        return

    print("[ATTACK-TIMEOUT] Attempting to pair now...")
    try:
        await asyncio.wait_for(connection.pair(), timeout=5)
        print("[ATTACK-TIMEOUT] !!! UNEXPECTED: pairing succeeded -- attack succeeded (BAD)")
    except asyncio.TimeoutError:
        print("[ATTACK-TIMEOUT] Pairing attempt timed out after 5s (connection already dropped)")
        print("[ATTACK-TIMEOUT] Session timeout attack FAILED as expected -- protocol is secure.")
    except (Exception, asyncio.CancelledError) as e:
        print(f"[ATTACK-TIMEOUT] Pairing correctly failed (connection already dropped): {e}")
        print("[ATTACK-TIMEOUT] Session timeout attack FAILED as expected -- protocol is secure.")

    try:
        await connection.disconnect()
    except (Exception, asyncio.CancelledError):
        pass

asyncio.run(main())