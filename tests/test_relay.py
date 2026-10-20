#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Root-only network-namespace integration tests for pppoe-relay.

No PPP daemon is needed: raw client/AC peers perform discovery and compare
forwarded PPP frames byte for byte. Run in a disposable VM, never on live links.
"""
import contextlib
import ctypes
import errno
import os
from pathlib import Path
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest

DISC, SESS = 0x8863, 0x8864
PADI, PADO, PADR, PADS, PADT = 0x09, 0x07, 0x19, 0x65, 0xA7
SERVICE, AC_NAME, HOST, COOKIE, RELAY, ERROR = 0x101, 0x102, 0x103, 0x104, 0x110, 0x203
CLIENT = bytes.fromhex('020000000101')
CLIENT2 = bytes.fromhex('020000000102')
CLIENT3 = bytes.fromhex('020000000103')
SERVER = bytes.fromhex('020000000201')
SERVER2 = bytes.fromhex('020000000202')
RELAY_C = bytes.fromhex('0200000001fe')
RELAY_S = bytes.fromhex('0200000002fe')
BROADCAST = b'\xff' * 6
NAMES = tuple(f'kr-{os.getpid()}-{side}' for side in ('client', 'relay', 'server'))
BINARY = Path(os.environ.get('PPPOE_RELAY', Path(__file__).resolve().parents[1] / 'pppoe-relay'))
PEER = Path(os.environ.get('PPPOE_RELAY_PEER', Path(__file__).resolve().parent / 'pppoe-peer'))


def command(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT)


@contextlib.contextmanager
def namespace(name):
    original = os.open('/proc/self/ns/net', os.O_RDONLY)
    target = os.open('/run/netns/' + name, os.O_RDONLY)
    try:
        os.setns(target, 0)
        yield
    finally:
        os.setns(original, 0)
        os.close(target)
        os.close(original)


def encode_tags(tags):
    return b''.join(struct.pack('!HH', kind, len(value)) + value for kind, value in tags)


def decode_tags(data):
    tags = []
    while data:
        if len(data) < 4:
            raise ValueError('short tag')
        kind, length = struct.unpack('!HH', data[:4])
        if len(data) < 4 + length:
            raise ValueError('short tag value')
        tags.append((kind, data[4:4 + length]))
        data = data[4 + length:]
    return tags


def connect_pppoe(fd, interface, mac, sid):
    address = struct.pack('=HI', 24, 0) + struct.pack('!H', sid) + mac + interface.encode().ljust(16, b'\0')
    libc = ctypes.CDLL(None, use_errno=True)
    libc.connect.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint]
    libc.connect.restype = ctypes.c_int
    buffer = ctypes.create_string_buffer(address)
    if libc.connect(fd.fileno(), buffer, len(address)):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def tcp_packet(family, index, size, port):
    """An individual, fully checksummed PPP/IP/TCP frame eligible for GRO."""
    data = bytes((index + offset) % 251 for offset in range(size))
    if family == 4:
        source, target = socket.inet_aton('192.0.2.1'), socket.inet_aton('192.0.2.2')
        pseudo = source + target + struct.pack('!BBH', 0, 6, 20 + size)
    else:
        source = socket.inet_pton(socket.AF_INET6, '2001:db8::1')
        target = socket.inet_pton(socket.AF_INET6, '2001:db8::2')
        pseudo = source + target + struct.pack('!I3xB', 20 + size, 6)
    tcp = struct.pack('!HHIIHHHH', port, 443, 1000 + index * size, 1,
                      0x5010, 65535, 0, 0)
    tcp = tcp[:16] + struct.pack('!H', checksum(pseudo + tcp + data)) + tcp[18:]
    if family == 4:
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 40 + size, index + 1,
                         0x4000, 64, 6, 0, source, target)
        ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
        return b'\x00\x21' + ip + tcp + data
    ip = struct.pack('!IHBB16s16s', 6 << 28, 20 + size, 6, 64, source, target)
    return b'\x00\x57' + ip + tcp + data


def send_batch(fd, frames):
    """Submit only ordinary Ethernet frames, never prebuilt GSO packets."""
    class Iovec(ctypes.Structure):
        _fields_ = [('base', ctypes.c_void_p), ('length', ctypes.c_size_t)]

    class Msghdr(ctypes.Structure):
        _fields_ = [('name', ctypes.c_void_p), ('namelen', ctypes.c_uint),
                    ('iov', ctypes.POINTER(Iovec)), ('iovlen', ctypes.c_size_t),
                    ('control', ctypes.c_void_p), ('controllen', ctypes.c_size_t),
                    ('flags', ctypes.c_int)]

    class Mmsghdr(ctypes.Structure):
        _fields_ = [('header', Msghdr), ('length', ctypes.c_uint)]

    buffers = [ctypes.create_string_buffer(frame) for frame in frames]
    vectors = (Iovec * len(frames))(*(Iovec(ctypes.addressof(buf), len(frame))
                                     for buf, frame in zip(buffers, frames)))
    messages = (Mmsghdr * len(frames))()
    for index in range(len(vectors)):
        messages[index].header.iov = ctypes.pointer(vectors[index])
        messages[index].header.iovlen = 1
    libc = ctypes.CDLL(None, use_errno=True)
    libc.sendmmsg.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint, ctypes.c_int]
    libc.sendmmsg.restype = ctypes.c_int
    sent = 0
    while sent < len(frames):
        count = libc.sendmmsg(fd.fileno(), ctypes.byref(messages, sent * ctypes.sizeof(Mmsghdr)),
                             len(frames) - sent, 0)
        if count < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        if not count:
            raise RuntimeError('sendmmsg made no progress')
        sent += count


class Port:
    def __init__(self, name):
        self.sockets = {}
        with namespace(name):
            for protocol in (DISC, SESS):
                fd = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(protocol))
                fd.bind(('eth0', 0))
                fd.setsockopt(263, 23, 1)  # SOL_PACKET, PACKET_IGNORE_OUTGOING
                self.sockets[protocol] = fd

    def close(self):
        for fd in self.sockets.values():
            fd.close()

    def send(self, protocol, destination, source, code=0, sid=0, payload=b''):
        frame = destination + source + struct.pack('!HBBHH', protocol, 0x11, code, sid, len(payload)) + payload
        self.sockets[protocol].send(frame)

    def receive(self, protocol, code=None, sid=None, timeout=3):
        end = time.monotonic() + timeout
        fd = self.sockets[protocol]
        while time.monotonic() < end:
            readable, _, _ = select.select([fd], [], [], max(0, end - time.monotonic()))
            if not readable:
                break
            data, address = fd.recvfrom(65536)
            if address[2] == 4 or len(data) < 20:
                continue
            ether, version, received_code, received_sid, length = struct.unpack('!HBBHH', data[12:20])
            if ether != protocol or version != 0x11 or len(data) < 20 + length:
                continue
            if code is not None and code != received_code:
                continue
            if sid is not None and sid != received_sid:
                continue
            return dict(destination=data[:6], source=data[6:12], code=received_code,
                        sid=received_sid, payload=data[20:20 + length], wire_length=len(data))
        raise TimeoutError(f'no packet protocol={protocol:#x} code={code} sid={sid}')


class RelayTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0:
            raise unittest.SkipTest('requires root and network namespace capabilities')
        cls.created_namespaces = []
        cls.addClassCleanup(cls.remove_topology)
        for name in NAMES:
            command('ip', 'netns', 'add', name)
            cls.created_namespaces.append(name)
            command('ip', '-n', name, 'link', 'set', 'lo', 'up')
        for side, peer, ns, local_mac, peer_mac in (
                ('c0', 'c-peer', NAMES[0], RELAY_C, CLIENT),
                ('s0', 's-peer', NAMES[2], RELAY_S, SERVER)):
            command('ip', '-n', NAMES[1], 'link', 'add', side, 'type', 'veth', 'peer', 'name', peer)
            command('ip', '-n', NAMES[1], 'link', 'set', peer, 'netns', ns, 'name', 'eth0')
            for name, dev, mac in ((NAMES[1], side, local_mac), (ns, 'eth0', peer_mac)):
                command('ip', '-n', name, 'link', 'set', dev, 'address', mac.hex(':'))
                command('ip', '-n', name, 'link', 'set', dev, 'up')

    @classmethod
    def remove_topology(cls):
        for name in reversed(cls.created_namespaces):
            subprocess.run(['ip', 'netns', 'del', name], capture_output=True)

    def setUp(self):
        command('ip', '-n', NAMES[1], 'link', 'set', 's0', 'up')
        self.client, self.server = Port(NAMES[0]), Port(NAMES[2])
        self.addCleanup(self.client.close)
        self.addCleanup(self.server.close)
        self.log = tempfile.TemporaryFile(mode='w+')
        self.addCleanup(self.log.close)
        self.process = subprocess.Popen(['ip', 'netns', 'exec', NAMES[1], str(BINARY),
                                         '-C', 'c0', '-S', 's0', '-n', '2', '-v'],
                                        stdout=self.log, stderr=self.log)
        self.addCleanup(self.stop)
        self.wait_for(lambda: 'READY ' in self.log_text())
        self.serial = 0

    def log_text(self):
        return os.pread(self.log.fileno(), os.fstat(self.log.fileno()).st_size, 0).decode()

    def wait_for(self, condition, timeout=5):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if condition():
                return
            time.sleep(0.02)
        self.fail('timed out waiting for relay state: ' + self.log_text())

    def stop(self):
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGCONT)
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()

    def rows(self):
        return command('ip', 'netns', 'exec', NAMES[1], 'cat', '/proc/net/pppoe').splitlines()[1:]

    def expect_empty(self):
        self.wait_for(lambda: not self.rows())

    def expect_no_packet(self, port, protocol=DISC):
        with self.assertRaises(TimeoutError):
            port.receive(protocol, timeout=0.15)

    def offer(self, client_mac=CLIENT, server_mac=SERVER):
        self.serial += 1
        tags = [(SERVICE, b'test'), (HOST, struct.pack('!I', self.serial)),
                (0x105, b'\x00\x00\x01vendor')]
        self.client.send(DISC, BROADCAST, client_mac, PADI, payload=encode_tags(tags))
        request = self.server.receive(DISC, PADI)
        self.assertEqual(request['source'], RELAY_S)
        self.assertEqual(request['destination'], BROADCAST)
        offered = decode_tags(request['payload']) + [(AC_NAME, b'test-ac'), (COOKIE, b'cookie')]
        self.server.send(DISC, RELAY_S, server_mac, PADO, payload=encode_tags(offered))
        response = self.client.receive(DISC, PADO)
        self.assertEqual(response['source'], RELAY_C)
        self.assertEqual(response['destination'], client_mac)
        selected = [(k, v) for k, v in decode_tags(response['payload']) if k != AC_NAME]
        self.client.send(DISC, RELAY_C, client_mac, PADR, payload=encode_tags(selected))
        request = self.server.receive(DISC, PADR)
        self.assertEqual(request['destination'], server_mac)
        accepted = decode_tags(request['payload'])
        self.assertIn((COOKIE, b'cookie'), accepted)
        self.assertIn(tags[1], accepted)
        self.assertEqual(sum(k == RELAY for k, _ in accepted), 1)
        return dict(client=client_mac, server=server_mac, tags=accepted, base=tags)

    def complete(self, context, sid=0x1234, extra=()):
        payload = encode_tags(context['tags'] + list(extra))
        self.server.send(DISC, RELAY_S, context['server'], PADS, sid, payload)
        pads = self.client.receive(DISC, PADS)
        self.assertEqual(pads['destination'], context['client'])
        self.assertEqual(pads['source'], RELAY_C)
        self.assertFalse(any(k == RELAY for k, _ in decode_tags(pads['payload'])))
        return dict(context, client_sid=pads['sid'], server_sid=sid, server_pads=payload, pads=pads)

    def session(self, client_mac=CLIENT, server_mac=SERVER, sid=0x1234):
        result = self.complete(self.offer(client_mac, server_mac), sid)
        self.assertGreater(result['client_sid'], 0)
        self.assertLess(result['client_sid'], 65535)
        return result

    def transfer(self, session, payload, reverse=False):
        source_port, target_port = (self.server, self.client) if reverse else (self.client, self.server)
        source_mac = session['server'] if reverse else session['client']
        target_mac = session['client'] if reverse else session['server']
        input_sid = session['server_sid'] if reverse else session['client_sid']
        output_sid = session['client_sid'] if reverse else session['server_sid']
        source_port.send(SESS, RELAY_S if reverse else RELAY_C, source_mac, sid=input_sid, payload=payload)
        received = target_port.receive(SESS, sid=output_sid)
        self.assertEqual(received['source'], RELAY_C if reverse else RELAY_S)
        self.assertEqual(received['destination'], target_mac)
        self.assertEqual(received['payload'], payload)

    def padt(self, session, reverse=False):
        source, target = (self.server, self.client) if reverse else (self.client, self.server)
        source.send(DISC, RELAY_S if reverse else RELAY_C,
                    session['server'] if reverse else session['client'], PADT,
                    session['server_sid'] if reverse else session['client_sid'],
                    encode_tags([(ERROR, b'normal termination')]))
        received = target.receive(DISC, PADT,
                                  session['client_sid'] if reverse else session['server_sid'])
        self.assertEqual(received['payload'], encode_tags([(ERROR, b'normal termination')]))

    def test_discovery_and_control_data_offload(self):
        session = self.session()
        self.assertEqual(len(self.rows()), 2)
        # Suspending the entire manager proves these frames cannot be relayed
        # by a userspace recv/send loop. PPP controls must take the same path.
        os.kill(self.process.pid, signal.SIGSTOP)
        try:
            controls = [0xC021, 0xC023, 0xC223, 0xC227, 0x8021, 0x8057, 0x80FD]
            for reverse in (False, True):
                for protocol in controls:
                    payload = struct.pack('!HBBH', protocol, 1, 7, 4)
                    self.transfer(session, payload, reverse)
                for protocol in (0x0021, 0x0057):
                    for size in (64, 512, 1494):
                        payload = struct.pack('!H', protocol) + bytes(i % 251 for i in range(size - 2))
                        self.transfer(session, payload, reverse)
        finally:
            os.kill(self.process.pid, signal.SIGCONT)

    def test_ipv4_ipv6_ping(self):
        session = self.session()
        peers = []
        try:
            for ns, mac, sid in ((NAMES[0], RELAY_C, session['client_sid']),
                                 (NAMES[2], RELAY_S, session['server_sid'])):
                peer = subprocess.Popen(['ip', 'netns', 'exec', ns, str(PEER), 'eth0', mac.hex(':'), str(sid)],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                peers.append(peer)
                readable, _, _ = select.select([peer.stdout], [], [], 5)
                self.assertTrue(readable, 'test peer did not start')
                iface = peer.stdout.readline().strip()
                self.assertRegex(iface, r'^ppp\d+$')
                command('ip', '-n', ns, 'link', 'set', iface, 'mtu', '1492', 'up')
                local, remote = ('1', '2') if ns == NAMES[0] else ('2', '1')
                command('ip', '-n', ns, 'addr', 'add', '172.20.0.' + local,
                        'peer', '172.20.0.' + remote, 'dev', iface)
                command('ip', '-n', ns, '-6', 'addr', 'add', 'fd00::' + local + '/64', 'dev', iface, 'nodad')
            for ns, remote in ((NAMES[0], '2'), (NAMES[2], '1')):
                for family, target, sizes in (('-4', '172.20.0.' + remote, (56, 512, 1464)),
                                               ('-6', 'fd00::' + remote, (56, 512, 1444))):
                    for size in sizes:
                        output = command('ip', 'netns', 'exec', ns, 'ping', family, '-n', '-q',
                                         '-c', '5', '-i', '0.05', '-W', '2', '-M', 'do', '-s', str(size), target)
                        self.assertIn('5 packets transmitted, 5 received, 0% packet loss', output)
        finally:
            for peer in peers:
                if peer.poll() is None:
                    peer.terminate()
                try:
                    peer.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    peer.kill()
                    peer.communicate()

    @unittest.skipUnless(os.environ.get('PPPOE_RELAY_GRO') == '1',
                         'set PPPOE_RELAY_GRO=1 to run GRO tests (requires ethtool)')
    def test_gro_forwarding(self):
        session = self.session()
        # Force standard-sized input frames and software segmentation on output.
        # Disable GRO at the destination so its capture sees final wire frames.
        for ns, dev in ((NAMES[0], 'eth0'), (NAMES[2], 'eth0'),
                        (NAMES[1], 'c0'), (NAMES[1], 's0')):
            command('ip', 'netns', 'exec', ns, 'ethtool', '-K', dev,
                    'tso', 'off', 'gso', 'off', 'tx', 'off', 'gro', 'off')
            features = command('ip', 'netns', 'exec', ns, 'ethtool', '-k', dev)
            for feature in ('tcp-segmentation-offload', 'generic-segmentation-offload',
                            'tx-checksumming', 'generic-receive-offload'):
                self.assertRegex(features, rf'(?m)^{feature}: off(?:\s|$)')
        os.kill(self.process.pid, signal.SIGSTOP)
        try:
            for fraglist in (False, True):
                for dev in ('c0', 's0'):
                    command('ip', 'netns', 'exec', NAMES[1], 'ethtool', '-K', dev,
                            'gro', 'on', 'rx-gro-list', 'on' if fraglist else 'off')
                    features = command('ip', 'netns', 'exec', NAMES[1], 'ethtool', '-k', dev)
                    self.assertRegex(features, r'(?m)^generic-receive-offload: on(?:\s|$)')
                    self.assertRegex(features, rf'(?m)^rx-gro-list: {"on" if fraglist else "off"}(?:\s|$)')
                    # Veth normally polls after each send. Coalesce across
                    # polls so this test does not depend on scheduling luck.
                    command('ip', 'netns', 'exec', NAMES[1], 'python3', '-c',
                            'from pathlib import Path; import sys; '
                            'p = Path("/sys/class/net") / sys.argv[1]; '
                            '(p / "gro_flush_timeout").write_text("10000000"); '
                            '(p / "napi_defer_hard_irqs").write_text("10")', dev)
                for family in (4, 6):
                    for reverse in (False, True):
                        with self.subTest(fraglist=fraglist, family=family, reverse=reverse):
                            self.gro_transfer(session, family, reverse, fraglist)
        finally:
            os.kill(self.process.pid, signal.SIGCONT)
            for dev in ('c0', 's0'):
                command('ip', 'netns', 'exec', NAMES[1], 'ethtool', '-K', dev,
                        'gro', 'off', 'rx-gro-list', 'off')

    def gro_transfer(self, session, family, reverse, fraglist):
        source, target = (self.server, self.client) if reverse else (self.client, self.server)
        source_mac, relay_mac, target_mac = ((SERVER, RELAY_S, CLIENT) if reverse
                                             else (CLIENT, RELAY_C, SERVER))
        input_sid = session['server_sid'] if reverse else session['client_sid']
        output_sid = session['client_sid'] if reverse else session['server_sid']
        size = 1452 if family == 4 else 1432
        count = 64
        port = 40000 + family * 10 + int(reverse) + 2 * int(fraglist)
        payloads = [tcp_packet(family, index, size, port) for index in range(count)]
        frames = [relay_mac + source_mac + struct.pack('!HBBHH', SESS, 0x11, 0,
                                                      input_sid, len(payload)) + payload
                  for payload in payloads]
        self.assertTrue(all(len(frame) == 1514 for frame in frames))
        # A protocol-specific AF_PACKET tap sees ingress after GRO. VNET_HDR
        # exposes gso_type/gso_size, proving actual aggregation rather than
        # merely testing an interface with the GRO feature enabled.
        with namespace(NAMES[1]):
            capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(SESS))
            capture.bind(('s0' if reverse else 'c0', 0))
            capture.setsockopt(263, 23, 1)  # PACKET_IGNORE_OUTGOING
            capture.setsockopt(263, 15, 1)  # PACKET_VNET_HDR
            capture.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        self.addCleanup(capture.close)
        target.sockets[SESS].setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        send_batch(source.sockets[SESS], frames)
        received = []
        for expected in payloads:
            packet = target.receive(SESS, sid=output_sid)
            self.assertEqual(packet['source'], RELAY_C if reverse else RELAY_S)
            self.assertEqual(packet['destination'], target_mac)
            self.assertEqual(packet['payload'], expected)
            self.assertEqual(packet['wire_length'], 1514)
            received.append(packet)
        aggregated = []
        represented = 0
        capture.settimeout(3)
        while represented < count:
            data = capture.recv(131072)
            _, gso_type, _, gso_size, _, _ = struct.unpack('=BBHHHH', data[:10])
            frame = data[10:]
            self.assertEqual(frame[:12], relay_mac + source_mac)
            self.assertEqual(struct.unpack('!H', frame[16:18])[0], input_sid)
            self.assertEqual(struct.unpack('!H', frame[18:20])[0], len(frame) - 20)
            if gso_type:
                self.assertEqual(gso_type, 1 if family == 4 else 4)
                self.assertEqual(gso_size, size)
                self.assertGreater(len(frame), 1514)
                aggregated.append(len(frame))
            tcp_data = len(frame) - 14 - 6 - 2 - (20 if family == 4 else 40) - 20
            self.assertEqual(tcp_data % size, 0)
            represented += tcp_data // size
        self.assertEqual(represented, count)
        self.assertTrue(aggregated, 'no GRO aggregation occurred')
        self.expect_no_packet(target, SESS)
        print(f'\nGRO IPv{family} {"AC->client" if reverse else "client->AC"} '
              f'fraglist={fraglist}: {len(aggregated)} aggregates, max={max(aggregated)}, '
              f'{len(received)}/{count} frames match', flush=True)
        capture.close()

    def test_duplicate_pads_reuses_channels(self):
        session = self.session()
        fd_count = len(os.listdir(f'/proc/{self.process.pid}/fd'))
        for _ in range(3):
            self.server.send(DISC, RELAY_S, SERVER, PADS, session['server_sid'], session['server_pads'])
            response = self.client.receive(DISC, PADS)
            self.assertEqual(response['sid'], session['client_sid'])
        self.assertEqual(len(os.listdir(f'/proc/{self.process.pid}/fd')), fd_count)
        self.assertEqual(self.log_text().count('session opened'), 1)

    def test_both_padt_directions_and_fd_reuse(self):
        baseline = len(os.listdir(f'/proc/{self.process.pid}/fd'))
        for iteration in range(6):
            session = self.session(sid=0x1200 + iteration)
            self.padt(session, reverse=bool(iteration % 2))
            self.expect_empty()
            self.wait_for(lambda: len(os.listdir(f'/proc/{self.process.pid}/fd')) == baseline)
            self.client.send(SESS, RELAY_C, CLIENT, sid=session['client_sid'], payload=b'\xc0\x21\x01\x01\x00\x04')
            self.expect_no_packet(self.server, SESS)

    def test_capacity_failure_and_recovery(self):
        first = self.session()
        second = self.session(CLIENT2, SERVER2, sid=0x1234)
        self.assertNotEqual(first['client_sid'], second['client_sid'])
        context = self.offer(CLIENT3)
        filler = b'x' * (1494 - len(encode_tags(context['tags'])) - 4)
        third = self.complete(context, sid=0x2345, extra=[(0x105, filler)])
        self.assertEqual(third['client_sid'], 0)
        self.assertTrue(any(k == ERROR for k, _ in decode_tags(third['pads']['payload'])))
        self.assertIn(third['base'][1], decode_tags(third['pads']['payload']))
        self.assertIn((0x105, filler), decode_tags(third['pads']['payload']))
        self.server.receive(DISC, PADT, 0x2345)
        self.assertEqual(len(self.rows()), 4)
        self.transfer(first, b'\xc0\x21\x01\x01\x00\x04')
        self.transfer(second, b'\xc0\x23\x01\x01\x00\x04', reverse=True)
        self.padt(first)
        self.wait_for(lambda: len(self.rows()) == 2)
        self.assertGreater(self.session(CLIENT3, sid=0x2345)['client_sid'], 0)

    def test_error_pads_does_not_allocate(self):
        result = self.complete(self.offer(), sid=0, extra=[(ERROR, b'service unavailable')])
        self.assertEqual(result['client_sid'], 0)
        self.assertIn((ERROR, b'service unavailable'), decode_tags(result['pads']['payload']))
        self.expect_empty()

    def test_partial_setup_failure_rolls_back(self):
        context = self.offer()
        # Occupy the AC-side tuple. The relay can open its client channel but
        # must close it again when the second PPPoE connect fails.
        with namespace(NAMES[1]):
            occupied = socket.socket(24, socket.SOCK_DGRAM, 0)
            connect_pppoe(occupied, 's0', SERVER, 0x1234)
        try:
            result = self.complete(context)
            self.assertEqual(result['client_sid'], 0)
            self.assertTrue(any(k == ERROR for k, _ in decode_tags(result['pads']['payload'])))
            self.server.receive(DISC, PADT, 0x1234)
            self.wait_for(lambda: len(self.rows()) == 1)
            payload = b'\xc0\x21\x01\x01\x00\x04'
            self.server.send(SESS, RELAY_S, SERVER, sid=0x1234, payload=payload)
            occupied.settimeout(2)
            self.assertEqual(occupied.recv(64), payload)
        finally:
            occupied.close()
        self.expect_empty()
        self.assertGreater(self.session()['client_sid'], 0)

    def test_unprivileged_duplicate_cleanup_preserves_owner(self):
        with namespace(NAMES[1]):
            occupied = socket.socket(24, socket.SOCK_STREAM, 0)
            connect_pppoe(occupied, 's0', SERVER, 0x1234)
        try:
            for action in ('close', 'disconnect', 'retry'):
                with self.subTest(action=action):
                    with namespace(NAMES[1]):
                        pid = os.fork()
                        if pid == 0:
                            try:
                                occupied.close()
                                os.setgroups([])
                                os.setgid(65534)
                                os.setuid(65534)
                                status = Path('/proc/self/status').read_text()
                                assert re.search(r'^CapEff:\s+0+$', status, re.M), status
                                fd = socket.socket(24, socket.SOCK_STREAM, 0)
                                try:
                                    connect_pppoe(fd, 's0', SERVER, 0x1234)
                                except OSError as error:
                                    assert error.errno == errno.EALREADY, error
                                else:
                                    raise AssertionError('duplicate connect succeeded')
                                if action == 'disconnect':
                                    connect_pppoe(fd, 's0', SERVER, 0)
                                elif action == 'retry':
                                    connect_pppoe(fd, 's0', SERVER, 0x2345)
                                fd.close()
                            except BaseException:
                                import traceback
                                traceback.print_exc()
                                os._exit(1)
                            os._exit(0)
                    _, status = os.waitpid(pid, 0)
                    self.assertEqual(os.waitstatus_to_exitcode(status), 0)
                    self.assertEqual(len(self.rows()), 1)
                    payload = b'\xc0\x21\x01\x01\x00\x04'
                    self.server.send(SESS, RELAY_S, SERVER, sid=0x1234, payload=payload)
                    occupied.settimeout(2)
                    self.assertEqual(occupied.recv(64), payload)
        finally:
            occupied.close()
        self.expect_empty()

    def test_spoofed_session_and_padt_are_ignored(self):
        session = self.session()
        self.client.send(SESS, RELAY_C, CLIENT2, sid=session['client_sid'], payload=b'\xc0\x21\x01\x01\x00\x04')
        self.expect_no_packet(self.server, SESS)
        self.client.send(DISC, RELAY_C, CLIENT2, PADT, session['client_sid'])
        self.expect_no_packet(self.server)
        self.assertEqual(len(self.rows()), 2)
        self.transfer(session, b'\xc0\x21\x01\x01\x00\x04')

    def test_collision_does_not_join_another_client(self):
        first = self.session()
        second = self.offer(CLIENT2)
        self.server.send(DISC, RELAY_S, SERVER, PADS, first['server_sid'], encode_tags(second['tags']))
        self.expect_no_packet(self.client)
        self.assertEqual(len(self.rows()), 2)
        self.transfer(first, b'\xc0\x21\x01\x01\x00\x04', reverse=True)

    def test_invalid_discovery(self):
        invalid = [b'\x01', b'\x01\x01\x00\x10short',
                   encode_tags([(RELAY, b'foreign')]),
                   encode_tags([(RELAY, b'a'), (RELAY, b'b')]),
                   encode_tags([(0, b''), (SERVICE, b'after-end')]),
                   encode_tags([(SERVICE, b'x' * 1490)])]
        for payload in invalid:
            self.client.send(DISC, BROADCAST, CLIENT, PADI, payload=payload)
            self.expect_no_packet(self.server)
        self.server.send(DISC, BROADCAST, SERVER, PADI, payload=encode_tags([(SERVICE, b'')]))
        self.expect_no_packet(self.client)
        self.client.send(DISC, BROADCAST, CLIENT, PADI, sid=42, payload=encode_tags([(SERVICE, b'')]))
        self.expect_no_packet(self.server)
        self.client.send(DISC, BROADCAST, CLIENT, PADI, payload=encode_tags([(SERVICE, b'test')]))
        request = self.server.receive(DISC, PADI)
        tags = decode_tags(request['payload'])
        bad_token = [(k, bytes([v[0] ^ 1]) + v[1:] if k == RELAY else v) for k, v in tags]
        self.server.send(DISC, RELAY_S, SERVER, PADO, payload=encode_tags(bad_token))
        self.expect_no_packet(self.client)
        self.expect_empty()

    def test_shutdown_notifies_both_peers(self):
        session = self.session()
        self.process.terminate()
        self.client.receive(DISC, PADT, session['client_sid'])
        self.server.receive(DISC, PADT, session['server_sid'])
        self.assertEqual(self.process.wait(timeout=5), 0)
        self.expect_empty()

    def test_link_down_cleans_up(self):
        session = self.session()
        command('ip', '-n', NAMES[1], 'link', 'set', 's0', 'down')
        self.client.receive(DISC, PADT, session['client_sid'])
        self.assertEqual(self.process.wait(timeout=5), 1)
        self.expect_empty()

    def test_channel_hup_cleans_up(self):
        session = self.session()
        # Kernel PPPoE accepts PADT independently of its tags. The manager drops
        # this malformed tag, then must notice that the PPP channel was closed.
        self.server.send(DISC, RELAY_S, SERVER, PADT, session['server_sid'], payload=b'x')
        self.client.receive(DISC, PADT, session['client_sid'])
        self.expect_empty()

    @unittest.skipUnless(os.environ.get('RP_PPPOE'), 'set RP_PPPOE for reference-client interoperability')
    def test_rp_pppoe_discovery_interoperability(self):
        process = subprocess.Popen(['ip', 'netns', 'exec', NAMES[0], os.environ['RP_PPPOE'],
                                    '-I', 'eth0', '-U', '-d', '-S', 'test', '-t', '1'],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            request = self.server.receive(DISC, PADI)
            tags = decode_tags(request['payload']) + [(AC_NAME, b'test-ac'), (COOKIE, b'cookie')]
            self.server.send(DISC, RELAY_S, SERVER, PADO, payload=encode_tags(tags))
            request = self.server.receive(DISC, PADR)
            self.server.send(DISC, RELAY_S, SERVER, PADS, 0x5678, request['payload'])
            output, error = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, error)
            match = re.search(r'(\d+):([0-9a-f:]{17})', output, re.I)
            self.assertIsNotNone(match, (output, error))
            self.assertEqual(match.group(2).lower(), RELAY_C.hex(':'))
            session = dict(client=CLIENT, server=SERVER, client_sid=int(match.group(1)), server_sid=0x5678)
            self.transfer(session, b'\xc0\x21\x01\x01\x00\x04')
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()


if __name__ == '__main__':
    unittest.main(verbosity=2)
