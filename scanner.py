import argparse

import time
from SnifferAPI import Sniffer
import SnifferAPI.Types as Types
import platform
#def list_silicon_devices():


def hexAddr(blist):
    return ":".join([hex(i)[2:] for i in blist])

def packet_to_string(packet):
        res = ""
        types = {Types.PACKET_TYPE_UNKNOWN:"UNKNOWN",
                    Types.PACKET_TYPE_ADVERTISING: "ADVERTISING",
                    Types.PACKET_TYPE_DATA: "DATA"}
        ble = packet.blePacket
        res = " ".join([res, str(packet.time), str(packet.RSSI)])
        if ble:
            dest = hexAddr(ble.scanAddress) if ble.scanAddress else "Broadcast"
            res = " ".join([res, "type:", types[ble.type], "src:", hexAddr(ble.advAddress), "dest:", dest])
            if ble.name[1:-1] != "":
                res += f" name: '{ble.name[1:-1]}'"
        return res

def get_default_device():
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
    return device_name

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("--device", help="Device name (/dev/ttyUSB0 or COM4)", default=get_default_device())
    parser.add_argument("--buckets", action="store_true")
    
    options = parser.parse_args()

    sniffer = Sniffer.Sniffer(options.device)
    sniffer.start()

    while True:
        for packet in sniffer.getPackets():
            print(packet_to_string(packet))
        time.sleep(.1) # really? is this *really* the best way?
main()
