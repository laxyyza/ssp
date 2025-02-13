import ctypes
import struct
import builtins
import ssppy._wrapper as ssp

ssp_callbacktype = ctypes.CFUNCTYPE(None, ctypes.c_voidp, ctypes.c_voidp, ctypes.c_voidp)

def ba_to_voidp(buffer: bytearray) -> ctypes.c_voidp:
    return ctypes.cast(
        ctypes.pointer(ctypes.c_char.from_buffer(buffer)), 
        ctypes.c_void_p
    ).value

def voidp_to_pyobj(voidp: ctypes.c_void_p) -> any:
    if voidp is None:
        return None
    return ctypes.cast(
        voidp,
        ctypes.POINTER(ctypes.py_object)
    ).contents.value

def pyobj_to_voidp(pyobj: object) -> ctypes.c_void_p:
    return ctypes.cast(
        ctypes.pointer(ctypes.py_object(pyobj)),
        ctypes.c_void_p
    )

def _dispatch_callback(segment: ssp._SSPSegment, p_user_data: ctypes.c_void_p, p_source_data: ctypes.c_void_p):
    ctx = voidp_to_pyobj(p_user_data)
    source_data = voidp_to_pyobj(p_source_data)
    data = ctypes.string_at(segment.contents.data, segment.contents.size)
    packet: SSPPacket = SSPPacket(segment.contents.packet.contents)

    ctx.dispatch_table[segment.contents.type](
        data, 
        ctx=ctx, 
        source_data=source_data,
        packet=packet,
        segment_type=segment.contents.type,
        size=segment.contents.size
    )

class SSPCtx:
    def __init__(self, magic=0):
        self._struct = ssp._SSPCtx()
        self._struct.user_data
        self.dispatch_table: dict[int, callable] = {}
        ssp.ssp_io_ctx_init(
            self._struct, 
            magic, 
            pyobj_to_voidp(self)
        )
        self.dispatch = ssp.SEGMENT_CALLBACK_TYPE(_dispatch_callback)
    
    def set_magic(self, magic: int) -> None:
        self._struct.magic = magic
    
    def create_io(self) -> "SSPIo":
        return SSPIo(self)
    
    def register(self, type: int, callback=None):
        def decorator(func):
            self.dispatch_table[type] = func
            ssp.ssp_io_ctx_register_dispatch(
                self._struct, 
                type, 
                self.dispatch
            )
        if callback == None:
            return decorator 
        else:
            decorator(callback)
        
class SSPDataRef:
    def __init__(self, data_ref: ssp._SSPDataRef):
        self._struct = data_ref
    
    def data(self) -> bytes:
        return ctypes.string_at(self._struct.contents.data)
    
class SSPIo:
    def __init__(self, ctx: SSPCtx, flags=0):
        self.ctx = ctx
        self._struct = ssp._SSPIo()
        ssp.ssp_io_init(self._struct, self.ctx._struct, flags)

    def __del__(self):
        ssp.ssp_io_deinit(self._struct)
    
    def push(self, *args, segment_type: int, important: bool=False) -> SSPDataRef:
        data = bytearray()
        
        for arg in args:
            match type(arg):
                case builtins.int:
                    data.extend(struct.pack("i", arg))
                case builtins.float:
                    data.extend(struct.pack("f", arg))
                case builtins.bytes:
                    data.extend(arg)
                case builtins.bytearray:
                    data.extend(arg)
                case builtins.str:
                    data.extend(arg.encode())
                case _:
                    raise ValueError(F"Unsupported type: {type(arg)}")
        
        size = len(data)
        voidp = ba_to_voidp(data)
        data_ref = None

        if important:
            data_ref = ssp.ssp_io_push_ref_i(self._struct, segment_type, size, voidp)
        else:
            data_ref = ssp.ssp_io_push_ref(self._struct, segment_type, size, voidp)
        
        return SSPDataRef(data_ref)

    
    def serialize(self) -> "SSPPacket":
        packet: SSPPacket = SSPPacket(self)
        return packet

class SSPPacket:
    def __init__(self, data: SSPIo|ssp._SSPPacket):
        if type(data) is SSPIo:
            self._struct = ssp.ssp_io_serialize(data._struct)
            self.io = data
        elif type(data) is ssp._SSPPacket:
            self._struct = data
            self.io = None
        else:
            raise TypeError(data)
    
    def __del__(self):
        if self.io:
            ssp.ssp_packet_free(self._struct)
    
    def data(self) -> bytes:
        return ctypes.string_at(self._struct.contents.buf, self._struct.contents.size)

class SSPIoProcessParams:
    def __init__(self, ctx: SSPCtx, io: SSPIo, buf: bytearray, peer_data=None, timestamp: float=0.0):
        self._struct = ssp._SSPIoProcessParams()
        self._struct.ctx = ctypes.pointer(ctx._struct)
        self._struct.io = ctypes.pointer(io._struct)
        self._struct.buf = ba_to_voidp(bytearray(buf))
        self._struct.size = ctypes.c_uint32(len(buf))
        self._struct.peer_data = pyobj_to_voidp(peer_data)
        self._struct.timestamp_s = ctypes.c_double(timestamp)
    
    def process(self) -> int:
        return ssp.ssp_io_process(self._struct)
