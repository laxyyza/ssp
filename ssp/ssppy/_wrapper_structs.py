import ctypes

__all__ = [
    "_SSPCtx", 
    "_SSPIo", 
    "_SSPSegment", 
    "_SSPPacket", 
    "_SSPFooter", 
    "_SSPDataRef", 
    "_SSPHeader", 
    "SEGMENT_CALLBACK_TYPE", 
]

class _SSPFooter(ctypes.Structure):
    _fields_ = [
        ("checksum", ctypes.c_uint32)
    ]

class _SSPHeader(ctypes.Structure):
    _fields_ = [
        ("magic", ctypes.c_uint32),
        ("flags", ctypes.c_uint8),
        ("segment_count", ctypes.c_uint8),
        ("payload_size", ctypes.c_uint16),
        ("session_id", ctypes.c_uint32),
        ("sequence_count", ctypes.c_uint16),
        ("ack", ctypes.c_uint32),
    ]

class _SSPPacket(ctypes.Structure):
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
        ("footer", ctypes.POINTER(_SSPFooter)),
        ("retries", ctypes.c_uint32),
        ("last_retry", ctypes.c_uint8),
        ("timestamp", ctypes.c_double),
    ]

class _SSPSegment(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_uint8),
        ("size", ctypes.c_uint16),
        ("data", ctypes.POINTER(ctypes.c_uint8)),
        ("packet", ctypes.POINTER(_SSPPacket)),
    ]

class _SSPCtx(ctypes.Structure):
    _fields_ = [
        ("dispatch_table", ctypes.c_voidp * 127),
        ("verifiy_session", ctypes.c_voidp),
        ("magic", ctypes.c_uint32),
        ("user_data", ctypes.c_voidp),
        ("current_time", ctypes.c_double),
    ]

class _SSPIo(ctypes.Structure):
    # TODO: Fill in struct ssp_io fields.
    _fields_ = [
        ("data", ctypes.c_uint8 * 1000)
    ]

class _SSPDataRef(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_uint8),
        ("size", ctypes.c_uint16),
        ("data", ctypes.c_voidp),
        ("important", ctypes.c_bool),
        ("copy", ctypes.c_voidp) # Callback function pointer
    ]

SEGMENT_CALLBACK_TYPE = ctypes.CFUNCTYPE(
    None, 
    ctypes.POINTER(_SSPSegment),
    ctypes.c_voidp,
    ctypes.c_voidp,
)