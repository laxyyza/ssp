import ctypes
import struct
import builtins
import ssppy._wrapper as ssp

ssp_callbacktype = ctypes.CFUNCTYPE(None, ctypes.c_voidp, ctypes.c_voidp, ctypes.c_voidp)

def ba_to_voidp(buffer: bytearray) -> ctypes.c_voidp:
    return ctypes.cast(ctypes.pointer(ctypes.c_char.from_buffer(buffer)), ctypes.c_void_p).value

class SSPCtx:
    def __init__(self, magic=0):
        self._struct = ssp._SSPCtx()
        ssp.ssp_io_ctx_init(self._struct, magic)
        self.dispatch_table: dict[int, callable] = {}
    
    def set_magic(self, magic: int) -> None:
        self._struct.magic = magic
    
    def create_io(self) -> "SSPIo":
        return SSPIo(self)
    
    def register(self, type: int, callback=None):
        def decorator(func):
            self.dispatch_table[type] = ssp.SEGMENT_CALLBACK_TYPE(func)
            ssp.ssp_io_ctx_register_dispatch(self._struct, type, self.dispatch_table[type])
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
    def __init__(self, io: SSPIo):
        self._struct = ssp.ssp_io_serialize(io._struct)
    
    def __del__(self):
        ssp.ssp_packet_free(self._struct)
    
    def data(self) -> bytes:
        return ctypes.string_at(self._struct.contents.buf, self._struct.contents.size)

class SSPIoProcessParams:
    def __init__(self, ctx: SSPCtx, io: SSPIo, buf: bytearray, size: int, peer_data=None, timestamp: float=0.0):
        self._struct = ssp._SSPIoProcessParams()
        self._struct.ctx = ctypes.pointer(ctx._struct)
        self._struct.io = ctypes.pointer(io._struct)
        self._struct.buf = ba_to_voidp(bytearray(buf))
        self._struct.size = ctypes.c_uint32(size)
        #self._struct.peer_data = ctypes.pointer(peer_data)
        #self._struct.timestamp_s = ctypes.c_double(timestamp)
    
    def process(self):
        ret = ssp.ssp_io_process(self._struct)
