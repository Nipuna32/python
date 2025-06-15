#!/usr/bin/python3

import socket
from struct import * 
from ctypes import *
import ctypes

class Ethernet_Header(Structure):
    _fields_ = [
            ("src_mac", c_uint8*6),
            ("dst_mac", c_uint8*6),
            ("ethernet_type",c_uint16)
            ]
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)
    
    def __init__(self, socket_buffer=None):
        self.type_map = {0x0800: "IPv4", 0x86DD: "IPv6"}
        try:
            self.TYPE = self.type_map[socket.ntohs(self.ethernet_type)]
        except:
            self.TYPE = str(socket.ntohs(self.ethernet_type))


class IPv4(Structure):
    _fields_ = [
            ("version", c_uint8, 4),
            ("ihl", c_uint8, 4),
            ("tos", c_ubyte),
            ("len", c_uint16),
            ("id",c_ushort),
            ("offset", c_ushort),
            ("ttl", c_uint8),
            ("protocol_num", c_ubyte),
            ("check_sum", c_uint16),
            ("src", c_uint32),
            ("dst",c_uint32)
            ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}
        
        self.IHL = self.version
        self.VER = self.ihl
        self.src_address = socket.inet_ntoa(pack("@I",self.src))
        self.dst_address = socket.inet_ntoa(pack("@I",self.dst))

        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)

class TCP(Structure):
    _fields_ = [
            ("src_port", c_uint16),
            ("dst_port", c_uint16),
            ("sequence_num", c_uint32),
            ("ack_num",c_uint32),
            ("hed_len",c_uint16,6),
            ("resev_bits",c_uint16,4),
            ("flag_urg",c_uint16,1),
            ("flag_ack",c_uint16,1),
            ("flag_psh",c_uint16,1),
            ("flag_rst",c_uint16,1),
            ("flag_syn",c_uint16,1),
            ("flag_fin",c_uint16,1),
            ("check_sum",c_uint16),
            ("window",c_uint16)
            ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)
    def __init__(self, socket_buffer=None):
        self.map_tcp = {21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS", 80:"HTTP", 443:"HTTPS"}
        self.seqnum = socket.ntohl(self.sequence_num)
        self.ackno  = socket.ntohl(self.ack_num)
        self.win    = socket.ntohs(self.window)

        self.source_port = socket.ntohs(self.src_port)
        self.destination_port = socket.ntohs(self.dst_port)
        
        if self.source_port in self.map_tcp:
            self.service = self.map_tcp[self.source_port]
        elif self.destination_port in self.map_tcp:
            self.service = self.map_tcp[self.destination_port]
        else:
            self.service = f"{self.source_port}|{self.destination_port}"

class IPv6(Structure):
    _fields_ = [
            ("version", c_uint32, 4),
            ("tclass",c_uint32, 8),
            ("payload_len",c_uint16),
            ("next_header",c_uint8),
            ("hop_limit",c_uint8),
            ("src",c_uint8*16),
            ("dst",c_uint8*16)
            ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.protocol_map = { 58:"ICMPv6", 6:"TCP", 17:"UDP"}

        self.src_add = socket.inet_ntop(socket.AF_INET6,self.src)
        self.dst_add = socket.inet_ntop(socket.AF_INET6,self.dst)
        try:
            self.next_hed = self.protocol_map[self.next_header]
        except:
            self.next_hed= str(self.next_header)

class UDP(Structure):
    _fields_ = [
            ("src",c_uint16),
            ("dst",c_uint16),
            ("len",c_uint16),
            ("sum",c_uint16)
            ]
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.src_port = socket.ntohs(self.src)
        self.dst_port = socket.ntohs(self.dst)
        self.length   = socket.ntohs(self.len)

class ICMP(Structure):
    _fields_ = [
            ("types",c_uint8),
            ("cod",c_uint8),
            ("sum",c_ushort),
            ("id", c_ushort),
            ("seq", c_ushort)
            ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.type_map = {0:"Echo", 3:"Unreachable", 8:"Echo_Reply"}

        try:
            self.sub_type = self.type_map[self.types]
        except:
            self.sub_type = str(self.types)


























