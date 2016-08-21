from _pynfq import ffi, lib
import os

#constants

class Packet:
    def __init__(self, conn, p):
        self.packet = p
        self.conn = conn

    def verdict(self, action, mangle=0):
        ret = lib.set_verdict(self.conn, self.packet[0], action, mangle)
        if ret:
            raise OSError(ret, 'Could not set packet verdict: ' + os.strerror(re))
        lib.add_empty(self.conn, self.packet[0], 1) #invalidate packet


#change to context manager!
class Connection:
    def __init__(self):
        num = 10
        size = 8192
        self.conn = ffi.new("struct nfq_connection *");
        lib.init_connection(self.conn, 0)
        self.buffers = []

        self.packets = ffi.new("struct nfq_packet[]", num);
        for i in range(num):
            b = ffi.new("char []", 8192)
            self.buffers.append(b)
            self.packets[i].buffer = b
            self.packets[i].len = 8192
        lib.add_empty(self.conn, self.packets, num)

    def __iter__(self):
        return self

    def __next__(self):
        p = ffi.new("struct nfq_packet * *")
        lib.get_packet(self.conn, p, 1)
        return Packet(self.conn, p)
        
    def bind(self, queue):
        ret = lib.bind_queue(self.conn, queue)
        if ret:
            raise OSError(ret, 'Could not bind queue: ' + os.strerror(re))

    def set_mode(self, queue, size, mode):
        ret = lib.set_mode(self.conn, queue, size, mode)
        if ret:
            raise OSError(ret, 'Could not change mode: ' + os.strerror(re))

    def close(self):
        lib.close_connection(self.conn)

