from typing import NoReturn
from cffi import FFI

MANGLE_CT: int
MANGLE_EXP: int
MANGLE_MARK: int
MANGLE_PAYLOAD: int
MANGLE_VLAN: int
NFQA_CAP_LEN: int
NFQA_CFG_F_CONNTRACK: int
NFQA_CFG_F_FAIL_OPEN: int
NFQA_CFG_F_GSO: int
NFQA_CFG_F_MAX: int
NFQA_CFG_F_SECCTX: int
NFQA_CFG_F_UID_GID: int
NFQA_CT: int
NFQA_CT_INFO: int
NFQA_EXP: int
NFQA_GID: int
NFQA_HWADDR: int
NFQA_IFINDEX_INDEV: int
NFQA_IFINDEX_OUTDEV: int
NFQA_IFINDEX_PHYSINDEV: int
NFQA_IFINDEX_PHYSOUTDEV: int
NFQA_L2HDR: int
NFQA_MARK: int
NFQA_PACKET_HDR: int
NFQA_PAYLOAD: int
NFQA_SECCTX: int
NFQA_SKB_INFO: int
NFQA_TIMESTAMP: int
NFQA_UID: int
NFQA_VERDICT_HDR: int
NFQA_VLAN: int
NFQNL_COPY_META: int
NFQNL_COPY_NONE: int
NFQNL_COPY_PACKET: int
NF_ACCEPT: int
NF_DROP: int
NF_QUEUE: int
NF_REPEAT: int
NF_STOLEN: int
NF_STOP: int

def be64toh(big_endian_64bits: int) -> int: ...
def init_connection(nfq_connection: FFI.CData) -> int: ...
def close_connection(nfq_connection: FFI.CData) -> NoReturn: ...
def send_msg(
    nfq_connection: FFI.CData,
    id: int,
    type: int,
    attr: FFI.CData,
    n: int,
    ack: int,
    seq: int,
) -> int: ...
def bind_queue(nfq_connection: FFI.CData, queue_id: int, ack: int, seq: int) -> int: ...
def unbind_queue(
    nfq_connection: FFI.CData, queue_id: int, ack: int, seq: int
) -> int: ...
def set_mode(
    nfq_connection: FFI.CData, queue_id: int, range: int, mode: int, ack: int, seq: int
) -> int: ...
def set_flags(
    nfq_connection: FFI.CData, queue_id: int, flags: int, mask: int, ack: int, seq: int
) -> int: ...
def set_maxlen(
    nfq_connection: FFI.CData, queue_id: int, len: int, ack: int, seq: int
) -> int: ...
def set_verdict(
    nfq_connection: FFI.CData,
    packet: FFI.CData,
    verdict: int,
    mangle: int,
    ack: int,
    seq: int,
) -> int: ...
def set_verdict_batch(
    nfq_connection: FFI.CData,
    packet: FFI.CData,
    verdict: int,
    mangle: int,
    ack: int,
    seq: int,
) -> int: ...
def receive(nfq_connection: FFI.CData, packets: FFI.CData, num: int) -> int: ...
def parse_packet(packet: FFI.CData) -> int: ...
