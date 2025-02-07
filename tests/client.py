#!/usr/bin/python3

import sys
import socket

sys.path.append("ssp")
from ssppy import *

SERVER_IP = "127.0.0.1"
SERVER_PORT = 49421

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

NET_MSG=1

# TODO: Implement callback and process.
def net_msg(io: SSPIo, data: bytes, user_data) -> None:
    pass

ssp_ctx = SSPCtx(0x69696969)
#ssp_ctx.register_dispatch(NET_MSG, )
ssp_io = ssp_ctx.create_io()

ssp_io.push("Ok", segment_type=1)
ssp_io.push("Hello", segment_type=1)

packet = ssp_io.serialize()

sys.stdout.buffer.write(packet.data())
sock.sendto(packet.data(), (SERVER_IP, SERVER_PORT))

del packet
