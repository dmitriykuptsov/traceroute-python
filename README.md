# traceroute-python
This is a simple Python-based traceroute utility. It is based on ICMP packets and increasing by one TTL field.
This utility requires 2n messages to complete.

Usage: sudo python3 traceroute.py --source [source IP] --destination [destination name or IP]

Example usage:

sudo python3 traceroute.py --source 192.168.2.45 --destination google.com
