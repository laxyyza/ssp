#!/usr/bin/python3

import socket
import sys

sys.path.append("ssp")
from ssppy import *

HOST = "0.0.0.0"
PORT = 49421

NET_MSG = 1
NET_ERROR = 2

ssp_ctx = SSPCtx(0x69696969)
ssp_io = ssp_ctx.create_io()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST, PORT))

@ssp_ctx.register(NET_MSG)
def net_msg(data: bytearray, source_data, **_):
    string = data.decode()
    print(f"Message from {source_data[0]}:{source_data[1]} - '{string}'")

@ssp_ctx.register(NET_ERROR)
def net_error(data: bytearray, source_data, **_):
    msg = data.decode()
    print(f"Error message from {source_data[0]}:{source_data[1]} - '{msg}'")

print(f"Listening on {HOST}:{PORT}")

while True:
    data, addr = sock.recvfrom(1024)   
    print(f"Recv {len(data)} bytes from {addr}:")

    params = SSPIoProcessParams(ssp_ctx, ssp_io, data, peer_data=addr)
    params.process()
