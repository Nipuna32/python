import socket
import struct
from ctypes import *
from datetime import datetime

class IP(Structure):
    _fields_ = [
        ("version", c_ubyte, 4),
        ("ihl", c_ubyte, 4),
        ("tos", c_ubyte),
        ("len", c_ushort),
        ("id", c_ushort),
        ("offset", c_ushort),
        ("ttl", c_ubyte),
        ("protocol_num", c_ubyte),
        ("sum", c_ushort),
        ("src", c_uint32),
        ("dst", c_uint32)
        ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):

        # map protocol constants to their names
        self.protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}

        self.src_address = socket.inet_ntoa(struct.pack("@I",self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("@I",self.dst))

        # human readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)
class TCP(Structure):
    _fields_ = [
        ("sorce_port", c_ushort),
        ("destination_port", c_ushort),
        ("sequence", c_uint32),
        ("ack", c_uint32),
        ("offset", c_ubyte, 4),
        ("reserved", c_ubyte),
        ("window", c_ushort),
        ("checksum", c_ushort),
        ("urgent", c_ushort)
        ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)    

    def __init__(self, socket_buffer=None):
        return None
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('ens33', 0))
while True:
    s = sock.recvfrom(65565)[0]
    ip = IP(s[:20:])
    tcp = TCP(s[14:])
    now = datetime.now()
    time = now.strftime("%H:%H:%S")
    print(time," IP (","version", ip.version, "-", "ihl", ip.ihl, "-", "tos", ip.tos,"-", "len", ip.len, "-", "id:", ip.id, ",", "offset", ip.offset, "-","ttl", ip.ttl, "-", "protocol", ip.protocol,")")
    print("source", ip.src, "-", "destination" , ip.dst, "-", "sequece", tcp.sequence, "-", "ack", tcp.ack, "-", "reserved", tcp.reserved, "-", "window", tcp.window, "-", "checksum", tcp.checksum, "-", "urgent", tcp.urgent,)
