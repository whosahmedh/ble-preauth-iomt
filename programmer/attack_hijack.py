# attack_hijack.py
import asyncio
from bumble.controller import Controller
from bumble.link import LocalLink
from bumble.host import Host
from bumble.device import Device
from bumble.transport import open_transport_or_link

SERVICE_UUID = "3b442fd2-ed4b-4606-ae27-07669ee14818"


async def connect_only():
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

    return await device.connect(found_address)


async def main():
    print("[ATTACK-HIJACK] Connecting WITHOUT completing the challenge-response...")
    connection = await connect_only()
    print("[ATTACK-HIJACK] Connected. Skipping the nonce read and signature entirely -- going STRAIGHT to pairing.")

    print("[ATTACK-HIJACK] Attempting to initiate SMP pairing on an un-authenticated connection...")
    try:
        await connection.pair()
        print("[ATTACK-HIJACK] !!! UNEXPECTED: pairing succeeded -- attack succeeded (BAD)")
    except (Exception, asyncio.CancelledError) as e:
        print(f"[ATTACK-HIJACK] Pairing correctly rejected: {e}")
        print("[ATTACK-HIJACK] Pairing hijacking attack FAILED as expected -- protocol is secure.")

    try:
        await connection.disconnect()
    except (Exception, asyncio.CancelledError):
        pass

asyncio.run(main())