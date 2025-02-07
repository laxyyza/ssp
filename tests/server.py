#!/usr/bin/python3

import socket
import sys

sys.path.append("ssp")
from ssppy import *

HOST = "0.0.0.0"
PORT = 49421

NET_MSG = 1

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST, PORT))

def net_msg(segmentp: ssp._SSPSegment, user_data, source_data):
    string = ctypes.string_at(segmentp.contents.data, segmentp.contents.size).decode()
    print(f"Type:{segmentp.contents.type} -> '{string}'")

ssp_ctx = SSPCtx(0x69696969)
ssp_ctx.register_dispatch(NET_MSG, net_msg)
ssp_io = ssp_ctx.create_io()

print(f"Listening on {HOST}:{PORT}")

while True:
    data, addr = sock.recvfrom(1024)   
    print(f"Recv {len(data)} bytes from {addr}:")

    params = SSPIoProcessParams(ssp_ctx, ssp_io, data, len(data))
    params.process()
