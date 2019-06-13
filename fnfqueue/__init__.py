"""An abstraction of the netlink nfqueue interface.

Packets can be retrieved by opening a Connection, configuring a queue, and
iterating over the Connection.

Example:

Initialize connection:
>>> conn = fnfqueue.Connection()

Bind to queue id 1 and copy full packet with maximum payload length. If not
executed with root rights or CAP_NET_ADMIN, a PermissionError (OSError in
python2 is raised. Additional queue attributes could be set here. E.g.
the maximum queue length, if you plan on holding back a lot of packets
(have a look at Queue).
>>> try:
...     q = conn.bind(1)
...     q.set_mode(fnfqueue.MAX_PAYLOAD, fnfqueue.COPY_PACKET)
... except PermissionError:
...     print("Access denied; Need root rights or CAP_NET_ADMIN")
...


Exemplary packet retrieval loop: Loop over packets in conn. This loop just
copies the payload for speed testing purposes and prints the packet arrival
time. The payload could be abitrarily modified here (up to a length of 65531
bytes). Finally the packet is resubmitted to the kernel. After mangle the
packet is invalid and can no longer be accessed.  In case packets arrive too
fast at the kernel side, the socket buffer overflows and a
BufferOverflowException is raised.
>>> while True:
...     try:
...         for packet in conn:
...             packet.payload = packet.payload
...             print(packet.time)
...             packet.mangle()
...     except fnfqueue.BufferOverflowException:
...         print("buffer error")
...

Close connection and release resources after being finished. This will cause
reading packets, calling verdict/mangle/bind/set_mode to raise StopIteration.
Close can be called from anywhere.
>>> conn.close()


Additional Notes:
 - Multiple packets are fetched at the same time from this library. This means,
   that for arrival time always Packet.time has to be used.
 - For some reason CTRL+C is only handled after a new packet arrives in python
   2. In python3 this only happens from time to time.
 - If a BufferOverflowException occured, reading packets or setting
   verdicts/mangling/bind/set_mode will raise BufferOverflowException until
   reset is called.
 - Missing not yet implemented attributes:
   * IFINDEX_*
   * HWADDR
   * CT
   * CT_INFO
   * SKB_INFO
   * EXP
   * SECCTX
   * VLAN
   * L2HDR
"""

from ._fnfqueue import ffi, lib
import threading
import os
import errno
import collections
import itertools
import socket
import datetime
import fcntl
import select

__all__ = ['Connection']

COPY_NONE = lib.NFQNL_COPY_NONE
COPY_META = lib.NFQNL_COPY_META
COPY_PACKET = lib.NFQNL_COPY_PACKET

DROP = lib.NF_DROP
ACCEPT = lib.NF_ACCEPT
REPEAT = lib.NF_REPEAT
STOP = lib.NF_STOP

MANGLE_MARK = lib.MANGLE_MARK
MANGLE_PAYLOAD = lib.MANGLE_PAYLOAD
MANGLE_CT = lib.MANGLE_CT
MANGLE_EXP = lib.MANGLE_EXP
MANGLE_VLAN = lib.MANGLE_VLAN

MAX_PAYLOAD = 0xffff

class PacketInvalidException(Exception):
    'Exception raised by accessing attributes of invalid Packet'
    pass

class BufferOverflowException(Exception):
    'Exception raised on buffer overflow during next(iter(Connection))'
    pass

class NoSuchAttributeException(KeyError):
    'Exception raised by accesing non existent attributes of Packet'
    pass

class Packet(object):
    """Holds data of a packet received from fnfqueue

    The packet can be mangled or a verdict be set."""
    def __init__(self, conn, p):
        self.cache = {}
        self.packet = p
        self._conn = conn
        self._mangle = 0
        self._invalid = False

    def mangle(self):
        """Accept the packet and mangle the modified attribute(s).

        After calling this function, using this instance is results
        in PacketInvalidException."""
        self.accept(self._mangle)

    def accept(self, mangle=0):
        """Accept the packet and optionally mangle the given attributes.

        mangle can be a combination (or) of MANGLE_MARK and MANGLE_PAYLOAD.

        After calling this function, using this instance is results
        in PacketInvalidException."""
        self.verdict(ACCEPT, mangle)

    def drop(self):
        """Drop the packet.

        After calling this function, using this instance is results
        in PacketInvalidException."""
        self.verdict(DROP, 0)

    def verdict(self, action, mangle=0):
        """Set the verdict action on the packet and optionally mangle the
        given attribute(s).

        action can be either DROP, ACCEPT, REPEAT, or STOP.

        mangle can be a combination (or) of MANGLE_MARK and MANGLE_PAYLOAD.

        After calling this function, using this instance is results
        in PacketInvalidException."""
        self._is_invalid()
        if mangle & lib.MANGLE_PAYLOAD:
            p = ffi.new("char []", self.cache['payload'])
            self.packet.attr[lib.NFQA_PAYLOAD].buffer = p
            self.packet.attr[lib.NFQA_PAYLOAD].len = len(self.cache['payload'])
        if mangle & lib.MANGLE_MARK:
            m = ffi.new("uint32_t *", socket.htonl(self.cache['mark']))
            self.packet.attr[lib.NFQA_MARK].buffer = m
            self.packet.attr[lib.NFQA_MARK].len = ffi.sizeof("uint32_t")
        if self._conn._conn is not None:
            ret = lib.set_verdict(self._conn._conn, self.packet, action, mangle, 0, 0)
        self._conn._recycle(self.packet)
        self._invalidate()
        if ret == -1:
            raise OSError(ffi.errno, os.strerror(ffi.errno))

    def _invalidate(self):
        del self.cache
        del self.packet
        del self._conn
        self._invalid = True

    def _is_invalid(self):
        if self._invalid:
            raise PacketInvalidException()

    @property
    def hw_protocol(self):
        """HW protocol id of packet. (Get only)"""
        self._is_invalid()
        return self.packet.hw_protocol

    @property
    def hook(self):
        """netfilter hook id of packet. (Get only)"""
        self._is_invalid()
        return self.packet.hook

    def _get_property(self, name, i, converted):
        self._is_invalid()
        if name in self.cache:
            return self.cache[name]
        if self.packet.attr[i].buffer == ffi.NULL:
            raise NoSuchAttributeException()
        self.cache[name] = converted()
        return self.cache[name]

    def _get_property32(self, name, i):
        def to32():
            return socket.ntohl(ffi.cast("uint32_t *",
                    self.packet.attr[i].buffer)[0])
        return self._get_property(name, i, to32)

    @property
    def payload(self):
        """Packet payload. (Get and Set)

        truncated needs to be checked, if the whole payload was copied.

        Set value needs to be byte (str in python2) or some type
        implementing a conversion function.

        Raises NoSuchAttributeException if packet has no payload."""
        def toString():
            return ffi.unpack(ffi.cast("char *",
                        self.packet.attr[lib.NFQA_PAYLOAD].buffer),
                        self.packet.attr[lib.NFQA_PAYLOAD].len)
        return self._get_property('payload', lib.NFQA_PAYLOAD,
                toString)

    @payload.setter
    def payload(self, value):
        self._is_invalid()
        self.cache['payload'] = value
        self._mangle |= lib.MANGLE_PAYLOAD

    @payload.deleter
    def payload(self):
        self._is_invalid()
        self._mangle &= ~lib.MANGLE_PAYLOAD
        self.cache['payload'] = None

    @property
    def uid(self):
        """Packet uid. (Get)

        Raises NoSuchAttributeException if packet has no uid."""
        return self._get_property32('uid', lib.NFQA_UID)

    @property
    def gid(self):
        """Packet uid. (Get)

        Raises NoSuchAttributeException if packet has no uid."""
        return self._get_property32('gid', lib.NFQA_GID)

    @property
    def mark(self):
        """Packet mark. (Get and Set)

        Set mark needs to be an unsigned integer that fits into 32 bit.

        Raises NoSuchAttributeException if packet has no mark."""
        return self._get_property32('mark', lib.NFQA_MARK)

    @mark.setter
    def mark(self, value):
        self._is_invalid()
        self.cache['mark'] = value
        self._mangle |= lib.MANGLE_MARK

    @mark.deleter
    def mark(self):
        self._is_invalid()
        self._mangle &= ~lib.MANGLE_MARK
        self.cache['mark'] = None

    @property
    def cap_len(self):
        """Packet payload length. (Get)

        Raises NoSuchAttributeException if packet was not truncated."""
        return self._get_property32('cap_len', lib.NFQA_CAP_LEN)

    @property
    def truncated(self):
        """True if packet payload was truncated. (Get)"""
        self._is_invalid()
        return self.packet.attr[lib.NFQA_CAP_LEN].buffer != ffi.NULL

    @property
    def time(self):
        """Packet arrival time. (Get)

        Raises NoSuchAttributeException if packet does not contain an arrival time."""
        def toTime():
            t = ffi.cast("struct nfqnl_msg_packet_timestamp *",
                    self.packet.attr[lib.NFQA_TIMESTAMP].buffer)
            return datetime.datetime.fromtimestamp(
                    lib.be64toh(t.sec) + lib.be64toh(t.usec)/1e6)
        return self._get_property('time', lib.NFQA_TIMESTAMP,
                toTime)

    #TODO: add attributes:
    #IFINDEX_INDEV get  add rtnelink to translate index -> dev
    #IFINDEX_OUTDEV get
    #IFINDEX_PHYSINDEV get
    #IFINDEX_PHYSOUTDEV get
    #HWADDR get
    #CT get set
    #CT_INFO get
    #SKB_INFO get
    #EXP set
    #SECCTX get
    #VLAN get set
    #L2HDR get


class _PacketErrorQueue(object):
    def __init__(self):
        self._packet_queue = collections.deque()
        self._packet_cond = threading.Condition()
        self._error_queue = {}
        self._error_cond = threading.Condition()
        self._exception = None

    def append(self, packets):
        with self._packet_cond:
            self._packet_queue.extend((p for p in packets if p.seq == 0))
            if len(self._packet_queue):
                self._packet_cond.notify()
        with self._error_cond:
            self._error_queue.update({p.seq:p for p in packets if p.seq != 0})
            if len(self._error_queue):
                self._error_cond.notify_all()

    def exception(self, e):
        with self._packet_cond, self._error_cond:
            self._exception = e
            self._error_cond.notify_all()
            self._packet_cond.notify_all()

    def get_packet(self):
        with self._packet_cond:
            while not len(self._packet_queue) and self._exception is None:
                self._packet_cond.wait()
            if self._exception is None:
                return self._packet_queue.popleft()
            return self._exception

    def get_error(self, seq):
        with self._error_cond:
            while seq not in self._error_queue and self._exception is None:
                self._error_cond.wait()
            if self._exception is None:
                return self._error_queue.pop(seq)
            return self._exception

    def clear(self):
        with self._error_cond, self._packet_cond:
            if isinstance(self._exception, BufferOverflowException):
                self._exception = None
                self._error_cond.notify_all()
                self._packet_cond.notify_all()

    def stop(self):
        self.exception(StopIteration())


class Queue(object):
    def __init__(self, conn, queue):
        self._conn = conn
        self._flags = 0
        self._queue = queue

    @property
    def id(self):
        """queue id"""
        return self._queue

    def unbind(self):
        """Unbind from fnfqueue queue"""
        self._conn._call(lib.unbind_queue, self._queue)
        del self._conn.queues[self._queue]

    def set_mode(self, size, mode):
        """Set copy mode and copy size of fnfqueue queue.

        Maximum size can be MAX_PAYLOAD, which results in a maximum
        possible payload size of 65531. Copy mode can be either
        COPY_NONE, which results in no transmitted packets, COPY_META,
        which results in packets without payload, and COPY_PACKET,
        which results in full packets."""
        self._conn._call(lib.set_mode, self._queue, size, mode)

    def set_maxlen(self, l):
        """Set the maximum number of packets enqueued in the kernel. Defaults
        to 1024.

        This is the maximum number of packets without a verdict. Additional
        packets are either dropped or accepted, if fail_open is set."""
        self._conn._call(lib.set_maxlen, self._queue, l)

    def _set_flag(self, flag, value):
        if value:
            self._flags |= flag
            self._conn._call(lib.set_flags, self._queue, flag, flag)
        else:
            self._flags &= ~flag
            self._conn._call(lib.set_flags, self._queue, flag, flag)

    def _get_flag(self, flag):
        return bool(self._flags & flag)

    @property
    def fail_open(self):
        """If True, packets are are accepted on queue overflow instead
        of dropped

        Defaults to false."""
        return self._get_flag(lib.NFQA_CFG_F_FAIL_OPEN)

    @fail_open.setter
    def fail_open(self, value):
        self._set_flag(lib.NFQA_CFG_F_FAIL_OPEN, value)

    @property
    def conntrack(self):
        """If True packets also contain conntrack information

        Defaults to false."""
        return self._get_flag(lib.NFQA_CFG_F_CONNTRACK)

    @conntrack.setter
    def conntrack(self, value):
        self._set_flag(lib.NFQA_CFG_F_CONNTRACK, value)

    @property
    def gso(self):
        """If True, packets are not reassembled in the kernel

        Defaults to false."""
        return self._get_flag(lib.NFQA_CFG_F_GSO)

    @gso.setter
    def gso(self, value):
        self._set_flag(lib.NFQA_CFG_F_GSO, value)

    @property
    def uid_gid(self):
        """If true packets contain uid and gid if available

        Defaults to false."""
        return self._get_flag(lib.NFQA_CFG_F_UID_GID)

    @uid_gid.setter
    def uid_gid(self, value):
        return self._set_flag(lib.NFQA_CFG_F_UID_GID, value)

    @property
    def secctx(self):
        """If true packets contain the security context if available

        Defaults to false."""
        return self._get_flag(lib.NFQA_CFG_F_SECCTX)

    @secctx.setter
    def secctx(self, value):
        self._set_flag(lib.NFQA_CFG_F_SECCTX, value)

#invalidate


class Connection(object):
    """Create a nfnetlink connection and needed buffers with given buffer settings.

    Buffers are allocated in alloc_size steps with a size of packet_size. A
    maximum of chunk_size messages is received from the kernel at once."""
    def __init__(self, alloc_size = 50, chunk_size = 10, packet_size = 20*4096): # just a guess for now
        self.alloc_size = alloc_size
        self.chunk_size = chunk_size
        self.packet_size = packet_size
        self.queue = {}
        self._conn = ffi.new("struct nfq_connection *")
        if lib.init_connection(self._conn) == -1:
            raise OSError(ffi.errno, os.strerror(ffi.errno))
        flags = fcntl.fcntl(self._conn.fd, fcntl.F_GETFL, 0)
        fcntl.fcntl(self._conn.fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        self._r, self._w = os.pipe()
        self._buffers = collections.deque()
        self._packets = collections.deque()
        self._packet_lock = threading.Lock()
        self._received = _PacketErrorQueue()
        self._worker = threading.Thread(target=self._reader)
        self._worker.daemon = True
        self._worker.start()
        self._seq = itertools.count(1)

    def _reader(self):
        chunk_size = self.chunk_size
        packets = ffi.new("struct nfq_packet*[]", chunk_size)
        while self._conn is not None:
            with self._packet_lock:
                if len(self._packets) < chunk_size:
                    self._alloc_buffers()
                packets[0:chunk_size] = itertools.islice(self._packets, chunk_size)
            num = lib.receive(self._conn, packets, chunk_size)
            if num == -1:
                if ffi.errno == errno.EAGAIN or ffi.errno == errno.EWOULDBLOCK:
                    res, _, _ = select.select([self._conn.fd, self._r], [], [])
                    if self._r not in res:
                        continue
                    break
                if ffi.errno == errno.ENOBUFS:
                    self._received.exception(BufferOverflowException())
                    continue
                else:
                    #SMELL: be more graceful?
                    #handle wrong filedescriptor for closeing connection
                    self._received.exception(OSError(ffi.errno, os.strerror(ffi.errno)))
                    return
            with self._packet_lock:
                self._received.append([self._packets.popleft() for i in range(num)])
        # shutdown
        os.close(self._r)
        self._received.stop()

    def _alloc_buffers(self):
        for _ in range(self.alloc_size):
            packet = ffi.new("struct nfq_packet *")
            b = ffi.new("char []", self.packet_size)
            self._buffers.append(b)
            packet.buffer = b
            packet.len = self.packet_size
            self._packets.append(packet)

    def _recycle(self, packet):
        with self._packet_lock:
            self._packets.append(packet)

    def __iter__(self):
        """Return an iterator with packets received from fnfqueue."""
        while True:
            p = self._received.get_packet()
            if isinstance(p, Exception):
                if isinstance(p, StopIteration):
                    return
                raise p
            err = lib.parse_packet(p)
            if err != 0:
                #this can only be result of set_verdict
                raise Exception('Hmm: {} {} {}'.format(p.seq, err, os.strerror(err)))
            else:
                yield Packet(self, p)

    def _call(self, fun, *args):
        seq = next(self._seq)
        args += (1, seq)
        if fun(self._conn, *args) == -1:
            raise OSError(ffi.errno, os.strerror(ffi.errno))
        res = self._received.get_error(seq)
        if isinstance(res, Exception):
            raise res
        err = lib.parse_packet(res)
        if err == -1: #ACK
            return
        if err == 0: #WTF
            raise Exception('Something went really wrong!')
        raise OSError(err, os.strerror(err))

    def bind(self, queue):
        """Bind to the the fnfqueue id queue."""
        self._call(lib.bind_queue, queue)
        self.queue[queue] = Queue(self, queue)
        return self.queue[queue]

    def reset(self):
        """Clear overflow exception."""
        self._received.clear()

    #change rcvbuffer

    def close(self):
        """Close the connection. This can also be called while packets are read,
        which will cause the loop to terminate."""
        if self._conn is not None:
            os.close(self._w)
            conn = self._conn
            self._conn = None
            lib.close_connection(conn)

