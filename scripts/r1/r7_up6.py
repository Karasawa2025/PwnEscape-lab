#!/usr/bin/env python3
# r7_up6.py <gw> -- one host IPv6 UDP datagram to fd01:0:<gw>::1 (rt6_probe trigger).
import socket, sys
gw = int(sys.argv[1], 0)
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.bind(("fd00:1::1", 0))
s.sendto(b"R7W", ("fd01:0:%x::1" % gw, 9))
