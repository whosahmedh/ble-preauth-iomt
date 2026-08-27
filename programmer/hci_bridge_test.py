# hci_bridge_test.py
import asyncio
from bumble.controller import Controller
from bumble.link import LocalLink
from bumble.host import Host
from bumble.device import Device
from bumble.device import Device, Peer
from bumble.transport import open_transport_or_link

async def main():
    link = LocalLink()

    print("Connecting to Renode HCI bridge on port 3456...")
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
    print("Scanning for the IoMT device...")

    found_address = None

    def on_advertisement(adv):
        nonlocal found_address
        if found_address is None:
            found_address = adv.address
            print(f"Found IoMT device: {found_address}")

    device.on('advertisement', on_advertisement)
    await device.start_scanning()

    for _ in range(50):
        if found_address:
            break
        await asyncio.sleep(0.1)
    await device.stop_scanning()

    if not found_address:
        print("Never found the device -- is Renode running and advertising?")
        return

    print(f"Connecting to {found_address}...")
    connection = await device.connect(found_address)
    print("Connected! Discovering services...")

    peer = Peer(connection)
    peer_services = await peer.discover_services()
    for service in peer_services:
        print(f"Service: {service.uuid}")
        characteristics = await service.discover_characteristics()
        for char in characteristics:
            print(f"  Characteristic: {char.uuid}")

    await connection.disconnect()
    print("Disconnected cleanly.")

asyncio.run(main())