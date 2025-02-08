#!/usr/bin/python3

import socket
import sys

sys.path.append("ssp")
from ssppy import *

HOST = "0.0.0.0"
PORT = 49421

NET_MSG = 1

ssp_ctx = SSPCtx(0x69696969)
ssp_io = ssp_ctx.create_io()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST, PORT))

@ssp_ctx.register(NET_MSG)
def net_msg(data: bytearray, ctx, source_data):
    string = data.decode()
    print(f"-> '{string}'")

print(f"Listening on {HOST}:{PORT}")

while True:
    data, addr = sock.recvfrom(1024)   
    print(f"Recv {len(data)} bytes from {addr}:")

    params = SSPIoProcessParams(ssp_ctx, ssp_io, data, len(data))
    params.process()
