import time
from SnifferAPI import Sniffer

sniffer = Sniffer.Sniffer("COM4")
sniffer.start()

def hexAddr(blist):
    return ":".join([hex(i)[2:] for i in blist])

while True:
    for packet in sniffer.getPackets():
        ble = packet.blePacket
        print(packet.time, packet.RSSI, end=" ")
        if ble:
            dest = hexAddr(ble.scanAddress) if ble.scanAddress else "Broadcast"
            print("type:", ble.advType, "src:", hexAddr(ble.advAddress), "dest:", dest, end=" ")
            if ble.name != "\"\"":
                print("name:", ble.name)
            print("")
        else:
            print("")
        #print(dir(packet))
    time.sleep(.1)