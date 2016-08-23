from _pynfq import ffi, lib
import os

#constants

class Packet:
    def __init__(self, conn, p):
        self.cache = {}
        self.packet = p
        self.conn = conn

    def verdict(self, action, mangle=0):
        ret = lib.set_verdict(self.conn, self.packet[0], action, mangle)
        if ret:
            raise OSError(ret, 'Could not set packet verdict: ' + os.strerror(re))
        lib.add_empty(self.conn, self.packet[0], 1) #invalidate packet

    def __getattr__(self, name):
        if name in self.cache:
            return self.cache[name]
        if name == 'payload':
            #cache buffer + change buffer to modifyable beyond len
            self.cache[name] = ffi.buffer(ffi.cast("char *",
                        self.packet[0].attr[lib.NFQA_PAYLOAD].buffer),
                        self.packet[0].attr[lib.NFQA_PAYLOAD].len)
            return self.cache[name]
        raise AttributeError

    def __setattr__(self, name, value):
        if name == 'cache':
            super().__setattr__(name, value)
        if name == 'payload':
            self.cache[name] = value
            self.packet[0].attr[lib.NFQA_PAYLOAD].buffer = ffi.new("char []", value)
            self.packet[0].attr[lib.NFQA_PAYLOAD].len = len(value)
        super().__setattr__(name, value)


#change to context manager!
class Connection:
    def __init__(self):
        self.num = 1
        self.size = 8192
        self.conn = ffi.new("struct nfq_connection *");
        lib.init_connection(self.conn, 0)
        self._userdata = ffi.new_handle(self)
        lib.set_empty_cb(self.conn, lib.empty_cb, self._userdata)
        self.buffers = []
        self.packets = []

    def add_buffers(self):
        packets = ffi.new("struct nfq_packet[]", self.num);
        self.packets.append(packets)
        for i in range(self.num):
            b = ffi.new("char []", 8192)
            self.buffers.append(b)
            packets[i].buffer = b
            packets[i].len = self.size 
        lib.add_empty(self.conn, packets, self.num)

    def __iter__(self):
        return self

    def __next__(self):
        p = ffi.new("struct nfq_packet * *")
        while lib.get_packet(self.conn, p, 1) != 1:
            pass
        return Packet(self.conn, p)
        
    def bind(self, queue):
        ret = lib.bind_queue(self.conn, queue)
        if ret:
            raise OSError(ret, 'Could not bind queue: ' + os.strerror(ret))

    def set_mode(self, queue, size, mode):
        ret = lib.set_mode(self.conn, queue, size, mode)
        if ret:
            raise OSError(ret, 'Could not change mode: ' + os.strerror(ret))

    def close(self):
        lib.close_connection(self.conn)


@ffi.def_extern()
def empty_cb(conn, s):
    print("empty")
    s = ffi.from_handle(s)
    s.add_buffers()
