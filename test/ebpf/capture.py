#!/usr/bin/env python3
"""Exercise the production collector with bounded maps and raw test packets.

Loads the BPF object embedded in the committed ebpf/ngx_ebpf.skel.h, i.e.
exactly what nginx ships. Requires root. Everything runs in an anonymous,
private network namespace. Map resizing is test-only; production defaults are
defined in ngx_ebpf.h.
"""
from contextlib import contextmanager
import ctypes as C
import errno
import os
import socket
import struct
import sys
import time

from fixture import Loader, Tap, Tuple, namespace, remote_backend, rules, skeleton_object


class Connection(C.Structure):
    _fields_ = [("phase", C.c_uint32),
                ("has_key", C.c_uint32), ("key", Tuple)]


class Expectation(C.Structure):
    _fields_ = [("cookie", C.c_uint64)]


VERSION = 2     # SYNACK_VERSION


class Record(C.Structure):
    _fields_ = [("version", C.c_uint32), ("length", C.c_uint32),
                ("headers", C.c_ubyte * 256)]


def key(family=2, src="127.0.0.2", dst="127.0.0.1", sport=23456,
        dport=54321, ack=42):
    k = Tuple(family=family, protocol=6, sport=socket.htons(sport),
              dport=socket.htons(dport), ack=socket.htonl(ack))
    source, dest = socket.inet_pton(family, src), socket.inet_pton(family, dst)
    k.src[:len(source)], k.dst[:len(dest)] = source, dest
    return k


def packet(k, *, flags=0x12, seq=100, payload=b"", extensions=0,
           fragment=False, jumbo=False, next_header=None, tcp_offset=5):
    tcp = struct.pack("!HHIIBBHHH", socket.ntohs(k.sport), socket.ntohs(k.dport),
                      seq, socket.ntohl(k.ack), tcp_offset << 4, flags, 8192, 0, 0)
    if k.family == 2:
        return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40 + len(payload), 123,
                           0x2000 if fragment else 0, 64, 6, 0,
                           bytes(k.src[:4]), bytes(k.dst[:4])) + tcp + payload
    ext = b""
    for i in range(extensions):
        ext += bytes([60 if i+1 < extensions else 6, 0]) + bytes(6)
    nxt = 60 if extensions else 6
    if fragment:
        nxt, ext = 44, bytes([6, 0, 0, 0, 0, 0, 0, 1])
    if next_header is not None:
        nxt = next_header
    size = 0 if jumbo else len(ext) + len(tcp) + len(payload)
    return struct.pack("!IHBB16s16s", 6 << 28, size, nxt, 64,
                       bytes(k.src), bytes(k.dst)) + ext + tcp + payload


# LRU maps keep a per-CPU cache of free slots, and a map only a few slots
# deep can evict while other CPUs still hold free ones: keep the test maps
# large enough for that never to happen, and overfill them to test eviction.
CAPACITY = {"conn": 1024, "expect": 2048, "capture": 1024}


class Collector:
    def __init__(self, path, tap):
        self.tap = tap
        self.proof = Loader(path, programs=(b"synack_in", b"synack_out"),
                           map_name=b"synack_conn", capacities={
                               ("synack_" + name).encode(): size
                               for name, size in CAPACITY.items()})
        self.lib = self.proof.lib
        self.fds = {name: self.lib.bpf_object__find_map_fd_by_name(self.proof.obj,
                    ("synack_" + name).encode())
                    for name in ("conn", "expect", "capture", "stats")}
        self.raw = {family: socket.socket(family, socket.SOCK_RAW, socket.IPPROTO_RAW)
                    for family in (2, 10)}
        self.raw[10].setsockopt(socket.IPPROTO_IPV6, 36, 1)  # IPV6_HDRINCL
        self.serial = 1 << 60

    def close(self):
        for s in self.raw.values():
            s.close()
        self.proof.close()

    def put(self, name, k, value, flags=0):
        rc = self.lib.bpf_map_update_elem(self.fds[name], C.byref(k), C.byref(value), flags)
        if rc:
            raise OSError(C.get_errno(), f"update {name}")

    def get(self, name, k, cls, consume=False):
        value = cls()
        fn = self.lib.bpf_map_lookup_and_delete_elem if consume else self.lib.bpf_map_lookup_elem
        if fn(self.fds[name], C.byref(k), C.byref(value)):
            if C.get_errno() == errno.ENOENT:
                return None
            raise OSError(C.get_errno(), f"lookup {name}")
        return value

    def delete(self, name, k):
        rc = self.lib.bpf_map_delete_elem(self.fds[name], C.byref(k))
        assert not rc or C.get_errno() == errno.ENOENT

    def owned(self, cookie):
        """Every expectation key in the map that still points at cookie."""
        keys, k, prev = [], Tuple(), None
        while self.lib.bpf_map_get_next_key(self.fds["expect"], prev, C.byref(k)) == 0:
            e = self.get("expect", k, Expectation)
            if e and e.cookie == cookie.value:
                keys.append(Tuple.from_buffer_copy(k))
            prev = C.byref(Tuple.from_buffer_copy(k))
        return keys

    def entries(self, name):
        k = (Tuple if name == "expect" else C.c_uint64)()
        n, prev = 0, None
        while self.lib.bpf_map_get_next_key(self.fds[name], prev, C.byref(k)) == 0:
            n += 1
            prev = C.byref(type(k).from_buffer_copy(k))
        return n

    def counter(self, number):
        return self.get("stats", C.c_uint32(number), C.c_uint64).value

    def register(self, k=None, cookie=None):
        self.serial += 1
        cookie = C.c_uint64(cookie or self.serial)
        state = Connection()
        if k is not None:
            state.key, state.has_key = k, 1
        self.put("conn", cookie, state)
        if k is not None:
            self.put("expect", k, Expectation(cookie.value))
        return cookie

    def clean(self, cookie):
        state = self.get("conn", cookie, Connection)
        if state and state.has_key:
            self.delete("expect", state.key)
        self.delete("conn", cookie)
        self.delete("capture", cookie)

    def send(self, k, data):
        n = 4 if k.family == 2 else 16
        self.raw[k.family].sendto(data, (socket.inet_ntop(k.family, bytes(k.dst[:n])), 0))
        # Raw send completion does not imply PREROUTING has run. In particular,
        # slow software-emulated guests can defer loopback RX to ksoftirqd.
        time.sleep(0.03)

    def capture_case(self, name, k, data, length=None):
        with self.tap.case(name):
            cookie = self.register(k)
            try:
                self.send(k, data)
                record = self.get("capture", cookie, Record, consume=True)
                if length is None:
                    assert record is None, name
                    assert self.get("conn", cookie, Connection).phase == 0, name
                else:
                    assert record and record.version == VERSION and record.length == length, (
                        name, "record", record, "state", self.get("conn", cookie, Connection),
                        "expectation", self.get("expect", k, Expectation))
                    assert bytes(record.headers[length:]) == bytes(256-length), name
                    # IPv4 raw sends cause the kernel to fill the IP checksum.
                    off = 20 if k.family == 2 else 0
                    assert bytes(record.headers[off:length]) == data[off:length], name
                    assert self.get("expect", k, Expectation) is None, name
                    assert self.get("conn", cookie, Connection) is None, name
                    self.send(k, data)
                    assert self.get("capture", cookie, Record) is None, name + " recreated after consumption"
            finally:
                self.clean(cookie)

    def non_synack(self, name, k):
        # Every inbound packet reaches synack_in; synack_candidate() must turn
        # these away even with the registered key's exact tuple and ACK.
        with self.tap.case(name):
            cookie = self.register(k)
            try:
                for flags in (0x10, 0x02, 0x18, 0x11, 0x14):   # ACK SYN PSH|ACK FIN|ACK RST|ACK
                    self.send(k, packet(k, flags=flags, payload=b"x" * 16))
                    assert self.get("capture", cookie, Record) is None, hex(flags)
                    assert self.get("conn", cookie, Connection).phase == 0, hex(flags)
                # the same key still captures a real SYN-ACK afterwards
                self.send(k, packet(k))
                assert self.get("capture", cookie, Record, consume=True)
            finally:
                self.clean(cookie)

    def synack_lifecycle(self):
        raw_cookie = int.from_bytes(self.raw[2].getsockopt(socket.SOL_SOCKET, 57, 8), sys.byteorder)
        cookie = self.register(cookie=raw_cookie)
        outgoing = key(src="127.0.0.2", dst="127.0.0.1", sport=40100, dport=40101, ack=0)
        reply = key(src="127.0.0.1", dst="127.0.0.2", sport=40101, dport=40100, ack=101)
        try:
            # One key: the wire tuple reversed, ACK S+1.
            self.send(outgoing, packet(outgoing, flags=2))
            state = self.get("conn", cookie, Connection)
            assert state.has_key and bytes(state.key) == bytes(reply), state.has_key
            # nginx never sends SYN data upstream: a SYN carrying data adds no
            # S+1+N key, and a SYN-ACK acknowledging the data does not match.
            self.send(outgoing, packet(outgoing, flags=2, payload=b"hello"))
            assert bytes(self.get("conn", cookie, Connection).key) == bytes(reply)
            data_ack = key(src="127.0.0.1", dst="127.0.0.2", sport=40101, dport=40100, ack=106)
            self.send(data_ack, packet(data_ack))
            assert self.get("capture", cookie, Record) is None
            # A retransmitted SYN keeps the same key, and re-adds it if the
            # LRU map evicted it.
            self.send(outgoing, packet(outgoing, flags=2))
            newer = self.get("conn", cookie, Connection)
            assert newer.has_key and bytes(newer.key) == bytes(state.key)
            assert self.get("expect", reply, Expectation).cookie == cookie.value
            self.delete("expect", reply)
            self.send(outgoing, packet(outgoing, flags=2))
            assert self.get("expect", reply, Expectation).cookie == cookie.value
            # A SYN with another sequence number cannot add a second key.
            previous = self.counter(1)                      # SECOND_KEY
            self.send(outgoing, packet(outgoing, flags=2, seq=999))
            assert bytes(self.get("conn", cookie, Connection).key) == bytes(reply)
            assert self.counter(1) > previous
            self.send(reply, packet(reply))
            assert self.get("capture", cookie, Record, consume=True)
            assert self.get("conn", cookie, Connection) is None
            assert not self.owned(cookie)
            # Terminal state: nothing is captured again after the handoff.
            self.send(outgoing, packet(outgoing, flags=2))
            self.send(reply, packet(reply))
            assert self.get("capture", cookie, Record) is None
        finally:
            self.clean(cookie)

    @contextmanager
    def tcp(self, address, hold=False):
        """A registered TCP connection to the remote backend; hold=True fills
        this cookie's capture slot first, so its SYN-ACK is seen but not stored."""
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as client:
            if family == socket.AF_INET6:
                # IPv4-mapped destinations send IPv4 packets from this socket.
                client.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            client.settimeout(3)
            value = int.from_bytes(client.getsockopt(socket.SOL_SOCKET, 57, 8), sys.byteorder)
            cookie = self.register(cookie=value)
            try:
                if hold:
                    self.put("capture", cookie, Record(version=VERSION, length=40))
                client.connect((address, 23456))
                yield cookie
            finally:
                self.clean(cookie)

    def tcp_case(self, name, address, expected_source):
        with self.tap.case("production " + name):
            # A missed capture leaves the registration with the one key the
            # SYN added: its wire tuple reversed, across NAT as well.
            with self.tcp(address, hold=True) as cookie:
                state = self.get("conn", cookie, Connection)
                assert state.phase == 0 and state.has_key, name
                assert [bytes(k) for k in self.owned(cookie)] == [bytes(state.key)], name
            # A stored capture deletes the registration and every key it owned.
            with self.tcp(address) as cookie:
                record = self.get("capture", cookie, Record, consume=True)
                assert record and record.version == VERSION, name
                data = bytes(record.headers[:record.length])
                # The packet family decides the header layout, not the socket.
                ipv4 = data[0] >> 4 == 4
                source = data[12:16] if ipv4 else data[8:24]
                expected = socket.AF_INET if ipv4 else socket.AF_INET6
                assert source == socket.inet_pton(expected, expected_source), name
                assert self.get("conn", cookie, Connection) is None, name
                assert not self.owned(cookie), name

    def remote(self):
        with remote_backend():
            self.tcp_case("remote IPv4", "192.0.2.2", "192.0.2.2")
            self.tcp_case("remote IPv6", "2001:db8:1::2", "2001:db8:1::2")
            self.tcp_case("remote IPv4-mapped socket", "::ffff:192.0.2.2", "192.0.2.2")
            with rules("chain out { type filter hook output priority raw; notrack; }\n"
                       "chain pre { type filter hook prerouting priority raw; notrack; }"):
                self.tcp_case("remote IPv4 untracked", "192.0.2.2", "192.0.2.2")
                self.tcp_case("remote IPv6 untracked", "2001:db8:1::2", "2001:db8:1::2")
            for name, address, original, out, post in [
                ("remote DNAT", "198.51.100.9", "192.0.2.2",
                 "ip daddr 198.51.100.9 tcp dport 23456 dnat ip to 192.0.2.2:23456", ""),
                ("remote SNAT", "192.0.2.2", "192.0.2.2", "",
                 "ip daddr 192.0.2.2 tcp dport 23456 snat ip to 192.0.2.1:34560-34569"),
                ("remote DNAT+SNAT", "198.51.100.10", "192.0.2.2",
                 "ip daddr 198.51.100.10 tcp dport 23456 dnat ip to 192.0.2.2:23456",
                 "ip daddr 192.0.2.2 tcp dport 23456 snat ip to 192.0.2.1:34570-34579"),
                ("remote IPv6 DNAT+SNAT", "2001:db8:2::9", "2001:db8:1::2",
                 "ip6 daddr 2001:db8:2::9 tcp dport 23456 dnat ip6 to [2001:db8:1::2]:23456",
                 "ip6 daddr 2001:db8:1::2 tcp dport 23456 snat ip6 to [2001:db8:1::1]:34580-34589"),
            ]:
                body = ""
                if out:
                    body += f"chain out {{ type nat hook output priority dstnat; {out}; }}\n"
                if post:
                    body += f"chain post {{ type nat hook postrouting priority srcnat; {post}; }}\n"
                with rules(body):
                    self.tcp_case(name, address, original)

    def collisions(self):
        outgoing = key(src="127.0.0.2", dst="127.0.0.1", sport=40200, dport=40201, ack=0)
        reply = key(src="127.0.0.1", dst="127.0.0.2", sport=40201, dport=40200, ack=101)
        first = self.register(reply)
        raw_cookie = int.from_bytes(self.raw[2].getsockopt(socket.SOL_SOCKET, 57, 8), sys.byteorder)
        second = self.register(cookie=raw_cookie)
        try:
            # The second live owner's SYN collides: the first keeps the key.
            before = self.counter(2)                        # COLLISION
            self.send(outgoing, packet(outgoing, flags=2))
            assert self.get("expect", reply, Expectation).cookie == first.value
            assert not self.get("conn", second, Connection).has_key
            assert self.counter(2) > before
            # A retransmitted SYN changes nothing.
            self.send(outgoing, packet(outgoing, flags=2))
            assert self.get("expect", reply, Expectation).cookie == first.value
            # The matching SYN-ACK is captured for the first owner only.
            self.send(reply, packet(reply))
            assert self.get("capture", first, Record, consume=True)
            assert self.get("capture", second, Record) is None
        finally:
            self.clean(first)
            self.clean(second)

    def expectation_eviction(self):
        # A full expectation map evicts instead of refusing the SYN's key.
        keys = [key(ack=10000+i) for i in range(2 * CAPACITY["expect"])]
        for k in keys:
            self.put("expect", k, Expectation(123))
        raw_cookie = int.from_bytes(self.raw[2].getsockopt(socket.SOL_SOCKET, 57, 8), sys.byteorder)
        cookie = self.register(cookie=raw_cookie)
        outgoing = key(src="127.0.0.2", dst="127.0.0.1", sport=40300, dport=40301, ack=0)
        try:
            assert self.entries("expect") <= CAPACITY["expect"]
            before = self.counter(0)
            self.send(outgoing, packet(outgoing, flags=2, seq=0xffffffff))
            assert self.counter(0) == before
            assert self.get("conn", cookie, Connection).has_key
            reply = key(src="127.0.0.1", dst="127.0.0.2", sport=40301, dport=40300, ack=0)
            self.send(reply, packet(reply))
            assert self.get("capture", cookie, Record)
        finally:
            for k in keys:
                self.delete("expect", k)
            self.clean(cookie)

    def capture_eviction(self):
        # A full capture map makes room by evicting the oldest records.
        held = [self.register() for _ in range(2 * CAPACITY["capture"])]
        for cookie in held:
            self.put("capture", cookie, Record(version=VERSION, length=40))
        k = key()
        cookie = self.register(k)
        try:
            before = self.counter(3)
            self.send(k, packet(k))
            assert self.counter(3) == before
            assert self.get("capture", cookie, Record)
            assert self.entries("capture") <= CAPACITY["capture"]
        finally:
            for c in held + [cookie]:
                self.clean(c)

    def connection_eviction(self):
        # Registering never fails for room: the oldest registrations go.
        held = [self.register() for _ in range(2 * CAPACITY["conn"])]
        try:
            assert self.entries("conn") <= CAPACITY["conn"]
            assert self.get("conn", held[-1], Connection)
        finally:
            for c in held:
                self.clean(c)

    def stale_owner_takeover(self):
        # A key left behind by a registration that no longer exists (owned by
        # cookie 123, never registered) is free: the next owner takes it over.
        # A key whose owner is still registered keeps that owner (see
        # collisions()).
        outgoing = key(src="127.0.0.2", dst="127.0.0.1", sport=40500, dport=40501, ack=0)
        reply = key(src="127.0.0.1", dst="127.0.0.2", sport=40501, dport=40500, ack=101)
        self.put("expect", reply, Expectation(123))
        raw_cookie = int.from_bytes(self.raw[2].getsockopt(socket.SOL_SOCKET, 57, 8), sys.byteorder)
        cookie = self.register(cookie=raw_cookie)
        try:
            before = self.counter(2)
            self.send(outgoing, packet(outgoing, flags=2))
            e = self.get("expect", reply, Expectation)
            assert e.cookie == cookie.value, e.cookie
            assert self.counter(2) == before
            self.send(reply, packet(reply))
            assert self.get("capture", cookie, Record)
        finally:
            self.delete("expect", reply)
            self.clean(cookie)


def main():
    if len(sys.argv) != 1:
        Tap.bail("usage: sudo python3 test/ebpf/capture.py")
    if os.geteuid():
        Tap.bail("capture.py must run as root")
    tap = Tap()
    try:
        namespace()
        obj = skeleton_object()
        try:
            c = Collector(obj, tap)
        finally:
            os.unlink(obj)      # libbpf has read the file by now
    except Exception as e:
        Tap.bail(f"cannot load the collector: {e}")
    try:
        k4 = key()
        k6 = key(10, "::1", "::1")
        c.capture_case("IPv4 headers exclude application payload", k4, packet(k4, payload=b"payload"), 40)
        c.capture_case("IPv6 headers exclude application payload", k6, packet(k6, payload=b"payload"), 60)
        c.capture_case("eight IPv6 extension headers", k6, packet(k6, extensions=8), 124)
        c.capture_case("nine IPv6 extension headers rejected", k6, packet(k6, extensions=9))
        c.capture_case("IPv4 fragments rejected", k4, packet(k4, fragment=True))
        c.capture_case("IPv6 fragments rejected", k6, packet(k6, fragment=True))
        c.capture_case("IPv6 jumbograms rejected", k6, packet(k6, jumbo=True))
        c.capture_case("ESP rejected", k6, packet(k6, next_header=50))
        c.capture_case("short TCP header rejected", k4, packet(k4, tcp_offset=4))
        # synack_candidate() turns these away before the full parse
        c.capture_case("truncated IPv4 TCP header rejected", k4, packet(k4)[:36])
        short6 = bytearray(packet(k6)[:50])
        short6[4:6] = struct.pack("!H", 10)           # payload length matches
        c.capture_case("truncated IPv6 TCP header rejected", k6, bytes(short6))
        c.capture_case("inaccessible TCP options rejected", k4, packet(k4, tcp_offset=15))
        c.capture_case("RST SYN-ACK rejected", k4, packet(k4, flags=0x16))
        c.non_synack("IPv4 non-SYN-ACK packets never captured", k4)
        c.non_synack("IPv6 non-SYN-ACK packets never captured", k6)
        options = bytearray(packet(k4))
        options[0] = 0x46
        options[2:4] = struct.pack("!H", 44)
        options[20:20] = bytes([1, 1, 1, 0])
        c.capture_case("IPv4 options preserved", k4, bytes(options), 44)
        oversized = bytearray(packet(k6))
        oversized[4:6] = struct.pack("!H", 216+20)
        oversized[6] = 60
        oversized[40:40] = bytes([6, 26]) + bytes(214)
        c.capture_case("oversized IPv6 header chain rejected", k6, bytes(oversized))
        for name, case in [
            ("ACK of SYN data misses, retransmission retention, alias limit, terminal state",
             c.synack_lifecycle),
            ("a colliding key keeps its first live owner", c.collisions),
            ("full expectation map evicts; ACK arithmetic wraps at 32 bits",
             c.expectation_eviction),
            ("full capture map evicts for a new capture", c.capture_eviction),
            ("full connection map evicts for a new registration", c.connection_eviction),
            ("a key whose owner is gone is taken over, not a collision",
             c.stale_owner_takeover),
        ]:
            with tap.case(name):
                case()
        # Each connection is its own point; this one covers the namespace,
        # veth pair and NAT rules around them.
        with tap.case("remote backend namespace set up and torn down"):
            c.remote()
    finally:
        c.close()
    sys.exit(tap.done())


if __name__ == "__main__":
    main()
