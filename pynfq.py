from _pynfq import ffi, lib
import threading
import os
try:
    import Queue as queue
except:
    import queue

COPY_PACKET = lib.NFQNL_COPY_PACKET
COPY_NONE = lib.NFQNL_COPY_NONE

DROP = lib.NF_DROP
ACCEPT = lib.NF_ACCEPT
STOLEN = lib.NF_STOLEN
QUEUE = lib.NF_QUEUE
REPEAT = lib.NF_REPEAT
STOP = lib.NF_STOP

MANGLE_MARK = lib.MANGLE_MARK
MANGLE_PAYLOAD = lib.MANGLE_PAYLOAD
MANGLE_CT = lib.MANGLE_CT
MANGLE_EXP = lib.MANGLE_EXP
MANGLE_VLAN = lib.MANGLE_VLAN

class PacketInvalidException(Exception):
    pass

class BufferToSmallException(Exception):
    pass

class Packet:
    def __init__(self, conn, p):
        self.cache = {}
        self.packet = p
        self._conn = conn
        self._mangle = 0

    def mangle(self):
        self.verdict(ACCEPT, self._mangle)

    def accept(self):
        self.verdict(ACCEPT, 0)

    def drop(self):
        self.verdict(DROP, 0)

    def verdict(self, action, mangle=0):
        if mangle & lib.MANGLE_PAYLOAD:
            b = ffi.new("char []", self.cache['payload'])
            self.packet.attr[lib.NFQA_PAYLOAD].buffer = b
            self.packet.attr[lib.NFQA_PAYLOAD].len = len(self.cache['payload'])
        if self._conn._conn is not None:
            ret = lib.set_verdict(self._conn._conn, self.packet, action, mangle)
        self._conn.recycle(self.packet)
        if ret:
            raise OSError(ret, 'Could not set packet verdict: ' + os.strerror(ret))
        self._invalidate()

    def _invalidate(self):
        pass #TODO

    @property
    def payload(self):
        if 'payload' in self.cache:
            return self.cache['payload']
        if self.packet.attr[lib.NFQA_CAP_LEN].buffer != ffi.NULL:
            raise BufferToSmallException()
        #change that to a custom buffer later
        self.cache['payload'] = ffi.unpack(ffi.cast("char *",
                        self.packet.attr[lib.NFQA_PAYLOAD].buffer),
                        self.packet.attr[lib.NFQA_PAYLOAD].len)
        return self.cache['payload']

    @payload.setter
    def payload(self, value):
        self.cache['payload'] = value
        self._mangle |= lib.MANGLE_PAYLOAD

    @payload.deleter
    def payload(self):
        self._mangle &= ~lib.MANGLE_PAYLOAD
        self.cache['payload'] = None

    #TODO: add other attributes


#change to context manager!
class Connection:
    def __init__(self, alloc_size = 10, chunk_size = 10, packet_size = 20*4096): # just a guess for now
        self.alloc_size = alloc_size
        self.chunk_size = chunk_size
        self.packet_size = packet_size
        self._conn = ffi.new("struct nfq_connection *");
        lib.init_connection(self._conn, 0)
        self._packets = []
        self._buffers = []
        self._free = self._alloc_buffers()
        self._freelock = threading.Condition()
        self._received = queue.Queue()
        self._worker = threading.Thread(target=self._reader, daemon=True)
        self._worker.start()

    def _reader(self):
        m = 0
        free = []
        while self._conn is not None:
            with self._freelock:
                free.extend(self._free)
                self._free = []
            if len(free) < self.chunk_size:
                free.extend(self._alloc_buffers())
            if len(free) > m:
                packets = ffi.new("struct nfq_packet*[]", len(free))
                m = len(free)
            packets[0:len(free)] = free
            num = lib.receive(self._conn, packets, len(free))
            if num < 0:
                #better error handling!
                self._received.put(OSError(-num, os.strerror(-num)))
                continue
            for i in range(num):
                self._received.put(packets[i])
            free = free[num:]

    def _alloc_buffers(self):
        ret = []
        print(self.alloc_size)
        for i in range(self.alloc_size):
            packet = ffi.new("struct nfq_packet *");
            b = ffi.new("char []", self.packet_size)
            self._buffers.append(b)
            packet.buffer = b
            packet.len = self.packet_size
            self._packets.append(packet)
            ret.append(packet)
        return ret

    def recycle(self, packet):
        with self._freelock:
            self._free.append(packet)
            self._freelock.notify()

    def __iter__(self):
        return self

    def __next__(self):
        p = self._received.get() # handle errors!
        if isinstance(p, Exception):
            raise p
        if p.error != 0:
            return Exception('Hmm: {}'.format(p.error))
        return Packet(self, p)
        
    def bind(self, queue):
        ret = lib.bind_queue(self._conn, queue)
        if ret:
            raise OSError(ret, 'Could not bind queue: ' + os.strerror(ret))

    def set_mode(self, queue, size, mode):
        ret = lib.set_mode(self._conn, queue, size, mode)
        if ret:
            raise OSError(ret, 'Could not change mode: ' + os.strerror(ret))

    def close(self):
        conn = self._conn
        self._conn = None
        lib.close_connection(conn)

