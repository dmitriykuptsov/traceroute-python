#!/usr/bin/python

# Copyright (C) 2024 strangebit

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

class Packet():
    pass

IPV4_PACKET_LENGTH = 0x14;
IPV4_VERSION_OFFSET = 0x0
IPV4_IHL_OFFSET = 0x0
IPV4_TYPE_OF_SERVICE_LENGTH = 0x1
IPV4_TYPE_OF_SERVICE_OFFSET = 0x1
IPV4_TOTAL_LENGTH_LENGTH = 0x2
IPV4_TOTAL_LENGTH_OFFSET = 0x2
IPV4_IDENTIFICATION_LENGTH = 0x2
IPV4_IDENTIFICATION_OFFSET = 0x4
IPV4_FLAGS_OFFSET = 0x6
IPV4_FRAGMENT_OFFSET = 0x6
IPV4_TTL_OFFSET = 0x8
IPV4_PROTOCOL_OFFSET = 0x9
IPV4_CHECKSUM_OFFSET = 0xA
IPV4_SRC_ADDRESS_OFFSET = 0xC
IPV4_SRC_ADDRESS_LENGTH = 0x4
IPV4_DST_ADDRESS_OFFSET = 0x10
IPV4_DST_ADDRESS_LENGTH = 0x4
IPV4_VERSION = 0x4
IPV4_LENGTH = 0x5
class IPv4Packet(Packet):
    def __init__(self, buffer = None):
        if not buffer:
            self.buffer = bytearray([0]) * IPV4_PACKET_LENGTH
            self.buffer[IPV4_VERSION_OFFSET] = (IPV4_VERSION << 4) | (IPV4_LENGTH & 0xF)
        else:
            self.buffer = buffer
    def set_total_length(self, length):
        self.buffer[IPV4_TOTAL_LENGTH_OFFSET] = (length >> 8) & 0xFF
        self.buffer[IPV4_TOTAL_LENGTH_OFFSET + 1] = (length & 0xFF)
    def get_total_length(self):
        length = self.buffer[IPV4_TOTAL_LENGTH_OFFSET]
        length |= self.buffer[IPV4_TOTAL_LENGTH_OFFSET + 1]
        return length
    def set_ttl(self, ttl):
        self.buffer[IPV4_TTL_OFFSET] = ttl & 0xFF
    def get_ttl(self):
        return self.buffer[IPV4_TTL_OFFSET]
    def set_protocol(self, protocol):
        self.buffer[IPV4_PROTOCOL_OFFSET] = protocol & 0xFF
    def get_protocol(self):
        return self.buffer[IPV4_PROTOCOL_OFFSET]
    def set_checksum(self, checksum):
        self.buffer[IPV4_CHECKSUM_OFFSET] = (checksum >> 8) & 0xFF
        self.buffer[IPV4_CHECKSUM_OFFSET + 1] = (checksum & 0xFF)
    def get_checksum(self):
        checksum = self.buffer[IPV4_CHECKSUM_OFFSET]
        checksum |= self.buffer[IPV4_CHECKSUM_OFFSET + 1]
        return checksum
    def set_source_address(self, src):
        self.buffer[IPV4_SRC_ADDRESS_OFFSET:IPV4_SRC_ADDRESS_OFFSET + IPV4_SRC_ADDRESS_LENGTH] = src 
    def get_source_address(self):
        return self.buffer[IPV4_SRC_ADDRESS_OFFSET:IPV4_SRC_ADDRESS_OFFSET + IPV4_SRC_ADDRESS_LENGTH]
    def set_destination_address(self, dst):
        self.buffer[IPV4_DST_ADDRESS_OFFSET:IPV4_DST_ADDRESS_OFFSET + IPV4_DST_ADDRESS_LENGTH] = dst 
    def get_destination_address(self):
        return self.buffer[IPV4_DST_ADDRESS_OFFSET:IPV4_DST_ADDRESS_OFFSET + IPV4_DST_ADDRESS_LENGTH]
    def set_payliad(self, payload):
        self.buffer = self.buffer + payload
    def get_payload(self):
        return self.buffer[IPV4_DST_ADDRESS_OFFSET + IPV4_DST_ADDRESS_LENGTH:]
    def get_header(self):
        return self.buffer[:IPV4_DST_ADDRESS_OFFSET + IPV4_DST_ADDRESS_LENGTH]
    def get_buffer(self):
        return self.buffer
    
ICMP_TYPE_OFFSET = 0x0
ICMP_TYPE_LENGTH = 0x1
ICMP_CODE_OFFSET = 0x1
ICMP_CODE_LENGTH = 0x1
ICMP_CHECKSUM_OFFSET = 0x2
ICMP_CHECKSUM_LENGTH = 0x2
ICMP_LENGTH = 0x4
ICMP_PROTOCOL_NUMBER = 0x1

class ICMPPacket(Packet):
    def __init__(self, buf=None):
        if not buf:
            self.buffer = bytearray([0]) * ICMP_LENGTH
        else:
            self.buffer = buf
    def set_type(self, type):
        self.buffer[ICMP_TYPE_OFFSET] = type
    def get_type(self):
        return self.buffer[ICMP_TYPE_OFFSET]
    def set_code(self, code):
        self.buffer[ICMP_CODE_OFFSET] = code
    def get_code(self):
        return self.buffer[ICMP_CODE_OFFSET]
    def set_checksum(self, checksum):
        self.buffer[ICMP_CHECKSUM_OFFSET] = (checksum >> 8) & 0xFF
        self.buffer[ICMP_CHECKSUM_OFFSET + 1] = (checksum & 0xFF)
    def get_buffer(self):
        return self.buffer;
    
ICMP_IDENTIFIER_OFFSET = 0x4
ICMP_IDENTIFIER_LENGTH = 0x2
ICMP_SEQUENCE_OFFSET = 0x6
ICMP_SEQUENCE_LENGTH = 0x2
ICMP_ECHO_REPLY_TYPE = 0x0
ICMP_TIME_EXCEEDED_TYPE = 0xB
ICMP_ECHO_TYPE = 0x8

class ICMPEchoPacket(ICMPPacket):
    def __init__(self, buffer = None):
        if not buffer:
            self.buffer = bytearray([0]) * (ICMP_TYPE_LENGTH + \
                                        ICMP_CODE_LENGTH + \
                                            ICMP_CHECKSUM_LENGTH + \
                                                ICMP_IDENTIFIER_LENGTH + \
                                                    ICMP_SEQUENCE_LENGTH)
        else:
            self.buffer = buffer
        
    def set_identifier(self, identifier):
        self.buffer[ICMP_IDENTIFIER_OFFSET] = (identifier >> 8) & 0xFF
        self.buffer[ICMP_IDENTIFIER_OFFSET + 1] = (identifier & 0xFF)
    def get_identifier(self):
        identifier = self.buffer[ICMP_IDENTIFIER_OFFSET]
        identifier = (identifier << 8) | self.buffer[ICMP_IDENTIFIER_OFFSET + 1]
        return identifier
    def set_sequence(self, sequence):
        self.buffer[ICMP_IDENTIFIER_OFFSET] = (sequence >> 8) & 0xFF
        self.buffer[ICMP_IDENTIFIER_OFFSET + 1] = (sequence & 0xFF)
    def get_sequence(self):
        sequence = self.buffer[ICMP_SEQUENCE_OFFSET]
        sequence = (sequence << 8) | self.buffer[ICMP_SEQUENCE_OFFSET + 1]
        return sequence
    
ICMP_IDENTIFIER_RESERVED_LENGTH = 0x4
ICMP_TIME_EXEEDED_PAYLOAD_OFFSET = 0x8

class ICMPTimeExceededPacket(ICMPPacket):
    def __init__(self, buffer = None):
        if buffer:
            self.buffer = buffer
        else:
            self.buffer = bytearray([0]) * (ICMP_TYPE_LENGTH + \
                                        ICMP_CODE_LENGTH + \
                                            ICMP_CHECKSUM_LENGTH + \
                                                ICMP_IDENTIFIER_RESERVED_LENGTH)
    def get_payload(self):
        return self.buffer[ICMP_TIME_EXEEDED_PAYLOAD_OFFSET:]