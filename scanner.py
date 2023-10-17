import time
from SnifferAPI import Sniffer
import SnifferAPI.Types as Types
import platform
#def list_silicon_devices():

def main():
    # TODO: Make this autodectable and manually configurable
    # just not hard coded for crying out loud.
    if platform.system() == "Windows":
        # Pyserial should let us enumerate COM ports
        device_name = "COM4"
    elif platform.system() == "Linux":
        # Enumeration is a pain, maybe trace /dev/ttyUSBX?
        # Maybe 'udevadm info --name=/dev/ttyUSB0 --attribute-walk'?
        # for each ttyUSB entry?
        device_name = "/dev/ttyUSB0"
    else:
        raise("I have no idea what OS this is:", platform.system())
    sniffer = Sniffer.Sniffer(device_name)
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
                if ble.name[1:-1] != "\"\"":
                    print(f"name: \"{ble.name[1:-1]}\"", end=" ")
                print("")
            else:
                print("")
            #print(dir(packet))
        time.sleep(.1)
main()
