import argparse

import time
from SnifferAPI import Sniffer
from SnifferAPI.Packet import Packet as APIPacket
import SnifferAPI.Types as Types
import platform
import math
import json
#def list_silicon_devices():

TYPES = {
    Types.PACKET_TYPE_UNKNOWN:"UNKNOWN",
    Types.PACKET_TYPE_ADVERTISING: "ADVERTISING",
    Types.PACKET_TYPE_DATA: "DATA"
}

ADV_TYPES = {
    Types.ADV_TYPE_ADV_IND : "ADV_IND",
    Types.ADV_TYPE_ADV_DIRECT_IND   : "ADVV_DIRECT_IND",
    Types.ADV_TYPE_ADV_NONCONN_IND  : "ADV_NONCONN_IND",
    Types.ADV_TYPE_ADV_SCAN_IND     : "ADV_SCAN_IND",
    Types.ADV_TYPE_SCAN_REQ         : "SCAN_REQ",
    Types.ADV_TYPE_SCAN_RSP         : "SCAN_RSP",
    Types.ADV_TYPE_CONNECT_REQ      : "CONNECT_REQ",
    Types.ADV_TYPE_ADV_EXT_IND      : "ADV_EXT_IND"
}

class Bucket:
    def __init__(self):
        self.count = 0
        self.avg_rssi = 0
        self.last_seen = 0

def hexAddr(blist):
    return ":".join([hex(i)[2:] for i in blist])

def packet_to_string(packet : APIPacket):
        res = ""
        ble = packet.blePacket
        res = " ".join([res, str(packet.time), str(packet.RSSI)])
        if ble:
            dest = hexAddr(ble.scanAddress) if ble.scanAddress else "Broadcast"
            res = " ".join([res, "type:", TYPES[ble.type], "src:", hexAddr(ble.advAddress), "dest:", dest])
            if ble.name[1:-1] != "":
                res += f" name: '{ble.name[1:-1]}'"
        return res

class Packet:
    def __init__(self, packet : APIPacket):
        self.packet = packet
    
    def to_json(self):
        packet = self.packet
        ble = self.packet.blePacket
        if not ble:
            return {"rssi": self.packet.RSSI}
        js = {
            "timestamp": packet.timestamp,
            "rssi": packet.RSSI,
            "src": hexAddr(ble.advAddress),
            "type": TYPES[ble.type],
        }
        if ble.type == Types.PACKET_TYPE_ADVERTISING:
            js["advType"] = ADV_TYPES[ble.advType]
        js["dest"] = hexAddr(ble.scanAddress) if ble.scanAddress else "Broadcast"
        if ble.name[1:-1] != "":
            js["name"] = ble.name[1:-1]
        return js

    def __str__(self):
        return packet_to_string(self.packet)


def update_buckets(packet : APIPacket, buckets : dict):
    ble = packet.blePacket
    if not ble:
        return
    addr = hexAddr(ble.advAddress)
    if addr not in buckets:
        bucket = Bucket()
        buckets[addr] = bucket
    bucket = buckets[addr]
    bucket.count += 1
    bucket.last_seen = packet.time
    bucket.name = ble.name
    # TODO: make average decay with time
    bucket.avg_rssi = (((bucket.avg_rssi*(bucket.count-1)) + packet.RSSI)/bucket.count)

def display_buckets(buckets : dict):
    #print("===")
    length = min(len(buckets), 10)
    for addr in reversed(sorted(buckets, key= lambda b: buckets[b].count)[-10:]):
        bucket = buckets[addr]
        print(f"{addr}: {bucket.count}/ {bucket.avg_rssi} {bucket.name}",end="")
        print(" "*20)
    if len(buckets) > 0:
        print(f"\x1b[{length}A",end="")

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
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--buckets", action="store_true")
    
    options = parser.parse_args()

    sniffer = Sniffer.Sniffer(options.device)
    sniffer.start()
    buckets = {}

    try:
        while True:
            for packet in sniffer.getPackets():
                packet = Packet(packet)
                if options.buckets:
                    update_buckets(packet.packet, buckets)
                    display_buckets(buckets)
                else:
                    if options.json:
                        print(packet.to_json())
                    else:
                        print(packet)
            time.sleep(.1) # really? is this *really* the best way?
    except Exception as e:
        print("\n"*min(len(buckets),10))
        raise(e)
    except KeyboardInterrupt:
        print("\n"*min(len(buckets),10))
main()
