#!/usr/bin/env python3

import ctypes
import socket

ssp = ctypes.CDLL("build/ssp/libssp.so")

class SSPFooter(ctypes.Structure):
    _fields_ = [
        ("checksum", ctypes.c_uint32)
    ]

class SSPHeader(ctypes.Structure):
    _fields_ = [
        ("magic", ctypes.c_uint32),
        ("flags", ctypes.c_uint8),
        ("segment_count", ctypes.c_uint8),
        ("payload_size", ctypes.c_uint16),
        ("session_id", ctypes.c_uint32),
        ("sequence_count", ctypes.c_uint16),
        ("ack", ctypes.c_uint32),
    ]

class SSPPacket(ctypes.Structure):
    _fields_ = [
        ("buf", ctypes.POINTER(ctypes.c_uint8)),
        ("size", ctypes.c_uint32),
        ("header_size", ctypes.c_uint32),
        ("payload_size", ctypes.c_uint32),
        ("ssp_header", ctypes.c_voidp),
        ("opt_data_buf", ctypes.c_voidp),
        ("opt_data_session_id", ctypes.POINTER(ctypes.c_uint32)),
        ("opt_data_seq", ctypes.POINTER(ctypes.c_uint16)),
        ("opt_data_ack_min", ctypes.POINTER(ctypes.c_uint16)),
        ("opt_data_ack_max", ctypes.POINTER(ctypes.c_uint16)),
        ("payload", ctypes.c_voidp),
        ("footer", ctypes.POINTER(SSPFooter)),
        ("retries", ctypes.c_uint32),
        ("last_retry", ctypes.c_uint8),
        ("timestamp", ctypes.c_double),
    ]

class SSPSegment(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_uint8),
        ("size", ctypes.c_uint16),
        ("data", ctypes.POINTER(ctypes.c_uint8)),
        ("packet", ctypes.POINTER(SSPPacket)),
    ]

class SSPCtx(ctypes.Structure):
    _fields_ = [
        ("dispatch_table", ctypes.c_voidp * 127),
        ("verifiy_session", ctypes.c_voidp),
        ("magic", ctypes.c_uint32),
        ("user_data", ctypes.c_voidp),
        ("current_time", ctypes.c_double),
    ]

class SSPIo(ctypes.Structure):
    # TODO: Fill in struct ssp_io fields.
    _fields_ = [
        ("data", ctypes.c_uint8 * 1000)
    ]

class SSPDataRef(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_uint8),
        ("size", ctypes.c_uint16),
        ("data", ctypes.c_voidp),
        ("important", ctypes.c_bool),
        ("copy", ctypes.c_voidp) # Callback function pointer
    ]

SEGMENT_CALLBACK_TYPE = ctypes.CFUNCTYPE(
    None, 
    ctypes.POINTER(SSPSegment),
    ctypes.c_voidp,
    ctypes.c_voidp,
)

ssp_io_ctx = ctypes.c_voidp

# void ssp_io_ctx_init(ctx, magic, user_data)
ssp.ssp_io_ctx_init.argtypes = [
    ctypes.POINTER(SSPCtx), 
    ctypes.c_uint32, 
    ctypes.c_voidp
]
ssp.ssp_io_ctx_init.restype = None

# void ssp_io_ctx_register_dispatch(ctx, type, callback)
ssp.ssp_io_ctx_register_dispatch.argtypes = [
    ctypes.POINTER(SSPCtx),
    ctypes.c_uint8,
    SEGMENT_CALLBACK_TYPE
]
ssp.ssp_io_ctx_register_dispatch.restype = None

# void ssp_io_init(io, ctx, flags)
ssp.ssp_io_init.argtypes = [
    ctypes.POINTER(SSPIo),
    ctypes.POINTER(SSPCtx),
    ctypes.c_uint8
]
ssp.ssp_io_init.restype = None

# ssp_data_ref_t* ssp_io_push_ref(io, type, size, data)
ssp.ssp_io_push_ref.argtypes = [
    ctypes.POINTER(SSPIo),
    ctypes.c_uint8,
    ctypes.c_uint16,
    ctypes.c_voidp
]
ssp.ssp_io_push_ref.restype = ctypes.POINTER(SSPDataRef)

# ssp_packet_t* ssp_io_serialize(io)
ssp.ssp_io_serialize.argtypes = [
    ctypes.POINTER(SSPIo),
]
ssp.ssp_io_serialize.restype = ctypes.POINTER(SSPPacket)


#
# Explain:
#

# ssp_ctx = SSPCtx()
# ssp.ssp_io_ctx_init(ctypes.pointer(ssp_ctx), 0x69696969, None)
#
# ssp_io = SSPIo()
# ssp.ssp_io_init(ctypes.pointer(ssp_io), ctypes.pointer(ssp_ctx), 0)
#
# msg = ctypes.create_string_buffer(32)
# msg.value = b"hello from python! :3"
#
# ssp.ssp_io_push_ref(ctypes.pointer(ssp_io), 0x69, len(msg.value), ctypes.cast(msg, ctypes.c_void_p))
# ssp.ssp_io_push_ref(ctypes.pointer(ssp_io), 0x11, len(msg.value), ctypes.cast(msg, ctypes.c_void_p))
#
# ssp_packet = ssp.ssp_io_serialize(ctypes.pointer(ssp_io))
#
# sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# sock.connect(("127.0.0.1", 49420))
#
# packet_bytes = ctypes.string_at(ssp_packet.contents.buf, ssp_packet.contents.size)
#
# sock.send(packet_bytes)
