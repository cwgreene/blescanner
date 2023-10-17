import time
from SnifferAPI import Sniffer
import SnifferAPI.Types as Types

sniffer = Sniffer.Sniffer("COM4")
sniffer.start()

def hexAddr(blist):
    return ":".join([hex(i)[2:] for i in blist])

while True:
    for packet in sniffer.getPackets():
        types = {Types.PACKET_TYPE_UNKNOWN:"UNKNOWN",
                 Types.PACKET_TYPE_ADVERTISING: "ADVERTISING",
                 Types.PACKET_TYPE_DATA: "DATA"}
        ble = packet.blePacket
        print(packet.time, packet.RSSI, end=" ")
        if ble:
            dest = hexAddr(ble.scanAddress) if ble.scanAddress else "Broadcast"
            print("type:", types[ble.type], "src:", hexAddr(ble.advAddress), "dest:", dest, end=" ")
            if ble.name != "\"\"":
                print("name:", ble.name)
            print("")
        else:
            print("")
        #print(dir(packet))
    time.sleep(.1)