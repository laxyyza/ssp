import ctypes
import ssppy._wrapper as ssp

class SSPCtx:
    def __init__(self, magic=0):
        self._struct = ssp._SSPCtx()
        ssp.ssp_io_ctx_init(self._struct, magic)
    
    def set_magic(self, magic: int) -> None:
        self._struct.magic = magic
    
    def create_io(self) -> "SSPIo":
        return SSPIo(self)
    
    def register_dispatch(self, type: int, callback) -> None:
        ssp.ssp_io_ctx_register_dispatch(self._struct, type, callback)
    
class SSPIo:
    def __init__(self, ctx: SSPCtx, flags=0):
        self.ctx = ctx
        self._struct = ssp._SSPIo()
        ssp.ssp_io_init(self._struct, self.ctx._struct, flags)

    def __del__(self):
        ssp.ssp_io_deinit(self._struct)
    
    def push(self, data, data_type: int, size: int=0, important: bool=False) -> None:
        # TODO: Figure out how the best way objects should be converted into bytes, user-friendly.
        if isinstance(data, str):
            string = data
            data = ctypes.create_string_buffer(len(string))
            data.value = string.encode()
        elif not isinstance(data, bytes):
            data = data.to_bytes(size)

        if data is not None and size == 0:
            size = len(data)
        
        print("data size: ", size)

        voidp = ctypes.cast(data, ctypes.c_void_p)

        if important:
            ssp.ssp_io_push_ref_i(self._struct, data_type, size, voidp)
        else:
            ssp.ssp_io_push_ref(self._struct, data_type, size, voidp)
    
    def serialize(self) -> "SSPPacket":
        return SSPPacket(self)

class SSPPacket:
    def __init__(self, io: SSPIo):
        self._struct = ssp.ssp_io_serialize(io._struct)
    
    def __del__(self):
        ssp.ssp_packet_free(self._struct)
    
    def data(self) -> bytes:
        return ctypes.string_at(self._struct.contents.buf, self._struct.contents.size)