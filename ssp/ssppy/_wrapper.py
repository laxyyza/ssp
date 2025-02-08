import ctypes

libssp_path: str = "build/ssp/libssp.so"

_libssp = ctypes.CDLL(libssp_path)

from ._wrapper_structs import *

#
# void ssp_io_ctx_init(ctx, magic, user_data)
#
_libssp.ssp_io_ctx_init.argtypes = [
    ctypes.POINTER(_SSPCtx), 
    ctypes.c_uint32, 
    ctypes.c_voidp
]
_libssp.ssp_io_ctx_init.restype = None

def ssp_io_ctx_init(ctx: _SSPCtx, magic: int, user_data=None) -> None:
    _libssp.ssp_io_ctx_init(ctypes.pointer(ctx), magic, user_data)

#
# void ssp_io_ctx_register_dispatch(ctx, type, callback)
#
_libssp.ssp_io_ctx_register_dispatch.argtypes = [
    ctypes.POINTER(_SSPCtx),
    ctypes.c_uint8,
    SEGMENT_CALLBACK_TYPE
]
_libssp.ssp_io_ctx_register_dispatch.restype = None

def ssp_io_ctx_register_dispatch(ctx: _SSPCtx, type: int, callback: ctypes.CFUNCTYPE) -> None:
    _libssp.ssp_io_ctx_register_dispatch(
        ctypes.pointer(ctx), 
        type, 
        callback
    )

#
# void ssp_io_init(io, ctx, flags)
#
_libssp.ssp_io_init.argtypes = [
    ctypes.POINTER(_SSPIo),
    ctypes.POINTER(_SSPCtx),
    ctypes.c_uint8
]
_libssp.ssp_io_init.restype = None

def ssp_io_init(io: _SSPIo, ctx: _SSPCtx, flags: int) -> None:
    _libssp.ssp_io_init(ctypes.pointer(io), ctypes.pointer(ctx), flags)

#
# void ssp_io_deinit(io)
#
_libssp.ssp_io_deinit.argtypes = [
    ctypes.POINTER(_SSPIo)
]
_libssp.ssp_io_deinit.restype = None

def ssp_io_deinit(io: _SSPIo) -> None:
    _libssp.ssp_io_deinit(ctypes.pointer(io))

#
# ssp_data_ref_t* ssp_io_push_ref(io, type, size, data)
#
_libssp.ssp_io_push_ref.argtypes = [
    ctypes.POINTER(_SSPIo),
    ctypes.c_uint8,
    ctypes.c_uint16,
    ctypes.c_voidp
]
_libssp.ssp_io_push_ref.restype = ctypes.POINTER(_SSPDataRef)

def ssp_io_push_ref(io: _SSPIo, type: int, size: int, data) -> _SSPDataRef:
    return _libssp.ssp_io_push_ref(ctypes.pointer(io), type, size, data)

#
# ssp_data_ref_t* ssp_io_push_ref_i(io, type, size, data)
#
_libssp.ssp_io_push_ref_i.argtypes = [
    ctypes.POINTER(_SSPIo),
    ctypes.c_uint8,
    ctypes.c_uint16,
    ctypes.c_voidp
]
_libssp.ssp_io_push_ref_i.restype = ctypes.POINTER(_SSPDataRef)

def ssp_io_push_ref_i(io: _SSPIo, type: int, size: int, data) -> _SSPDataRef:
    return _libssp.ssp_io_push_ref_i(ctypes.pointer(io), type, size, data)

#
# ssp_packet_t* ssp_io_serialize(io)
#
_libssp.ssp_io_serialize.argtypes = [
    ctypes.POINTER(_SSPIo),
]
_libssp.ssp_io_serialize.restype = ctypes.POINTER(_SSPPacket)

def ssp_io_serialize(io: _SSPIo) -> _SSPPacket:
    return _libssp.ssp_io_serialize(ctypes.pointer(io))

#
# ssp_packet_free(packet)
#
_libssp.ssp_packet_free.argtypes = [
    ctypes.POINTER(_SSPPacket)
]
_libssp.ssp_packet_free.restype = None

def ssp_packet_free(packet: _SSPPacket) -> None:
    _libssp.ssp_packet_free(packet)

#
# ssp_io_process(params)
#
_libssp.ssp_io_process.argtypes = [
    ctypes.POINTER(_SSPIoProcessParams)
]
_libssp.ssp_io_process.restype = ctypes.c_int32

def ssp_io_process(params: _SSPIoProcessParams) -> int:
    return _libssp.ssp_io_process(params)