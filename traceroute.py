#!/usr/bin/python3

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

__author__ = "Dmitriy Kuptsov"
__copyright__ = "Copyright 2024, strangebit"
__license__ = "GPL"
__version__ = "0.0.1b"
__maintainer__ = "Dmitriy Kuptsov"
__email__ = "dmitriy.kuptsov@strangebit.io"
__status__ = "development"

# Import the needed libraries
# RE library
import re
# Sockets
import socket
import select
# Timing
import time
# Timing 
from time import time
# Hex
# Network stuff
import socket
from utils import Checksum
import packets
import argparse
# Utils 
from utils import Misc

icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, packets.ICMP_PROTOCOL_NUMBER)
icmp_socket.bind(("0.0.0.0", packets.ICMP_PROTOCOL_NUMBER))
icmp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
icmp_socket.setblocking(0)

MAX_HOP_COUNT = 30

parser = argparse.ArgumentParser(
                    prog='pytracroute',
                    description='Traces the packet route from source to destination')

parser.add_argument("--source", dest="source", required=True)
parser.add_argument("--destination", dest="destination", required=True)

args = parser.parse_args()

if not re.match("^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}", args.destination):
    args.destination = socket.gethostbyname(args.destination.strip())

current_hop = 1
while True:
    icmp = packets.ICMPEchoPacket()
    icmp.set_type(packets.ICMP_ECHO_TYPE)
    icmp.set_identifier(1)
    icmp.set_sequence(current_hop)    
    icmp.set_checksum(Checksum.checksum(icmp.get_buffer()))
    buf = icmp.get_buffer()

    packet = packets.IPv4Packet()
    packet.set_ttl(current_hop)
    packet.set_source_address(Misc.ipv4_address_to_bytes(args.source))
    packet.set_destination_address(Misc.ipv4_address_to_bytes(args.destination))
    packet.set_protocol(packets.ICMP_PROTOCOL_NUMBER)
    checksum = Checksum.checksum(packet.get_header())
    packet.set_checksum(checksum)
    packet.set_payliad(buf)

    packet.set_total_length(int(len(packet.get_buffer())))
    start = time()

    icmp_socket.sendto(packet.get_buffer(), (args.destination, 0))
    ready = select.select([icmp_socket], [], [], 5)
    if ready[0]:
        buf = icmp_socket.recv(1522)
        end = time()
        ip = packets.IPv4Packet(buf)
        icmp = packets.ICMPPacket(ip.get_payload())
        
        if icmp.get_type() == packets.ICMP_ECHO_REPLY_TYPE or icmp.get_type() == packets.ICMP_TIME_EXCEEDED_TYPE:
            src = Misc.bytes_to_ipv4_string(ip.get_source_address())
            print(str(current_hop) + " source " + src + " delay (ms) " + str((end - start)* 1000))
            if src == args.destination:
                break
        else:
            print(str(current_hop) + " source * delay (ms) 0")    
    else:
        print(str(current_hop) + " source * delay (ms) 0")

    if current_hop + 1 > MAX_HOP_COUNT:
        break
    current_hop += 1