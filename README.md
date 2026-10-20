# PPPoE relay with kernel forwarding

`pppoe-relay` relays PPPoE between one client-facing Ethernet interface and one
access-concentrator-facing Ethernet interface. Discovery and session management
run in userspace. Established PPP session frames, including PPP control
protocols, are forwarded bidirectionally by the Linux kernel using
`PPPIOCBRIDGECHAN`.

## Build and run

Build requirements are GNU make, a C compiler and Linux system headers. The
relay has no external library dependencies.

```sh
make
sudo ./pppoe-relay -C eth0 -S eth1 -n 128
```

Bring both interfaces up with an MTU of at least 1500 first. Both interfaces
must be in the process's network namespace. Runtime requirements are:

- `CAP_NET_RAW` for discovery packet sockets;
- `CAP_NET_ADMIN` and access to `/dev/ppp` for PPP channel attachment;
- the Linux PPPoE driver and generic PPP channel bridging support
  (`PPPIOCBRIDGECHAN` and `PPPIOCUNBRIDGECHAN`).

The kernel modules can normally be loaded with `sudo modprobe pppoe`. Channel
bridging is provided by `ppp_generic`; no additional kernel relay module is
required.

Options:

| Option | Meaning |
| --- | --- |
| `-C interface` | Client-facing interface; specify exactly once |
| `-S interface` | Access-concentrator-facing interface; specify exactly once |
| `-n sessions` | Maximum active sessions; default 128, maximum 65534 |
| `-v` | Log malformed discovery packets |
| `-h` | Show usage |

Each active session uses four file descriptors. The process requires a soft
`RLIMIT_NOFILE` of at least `4 * sessions + 16` and reports an error if the limit
is insufficient. The relay always runs in the foreground. SIGINT or SIGTERM
sends PADT to both peers and releases all active sessions.

Optional installation:

```sh
sudo make install
# Or stage installation without root:
make install DESTDIR=/tmp/pppoe-relay-package PREFIX=/usr
```

## How it works

The discovery flow follows RP-PPPoE's userspace relay design:

1. Add a Relay-Session-Id tag to PADI and forward it toward the AC.
2. Use the tag to route PADO and PADR, swapping the return address at each step.
3. On successful PADS, allocate a client-facing session ID and connect two
   `AF_PPPOX`/`PX_PROTO_OE` sockets using each side's peer MAC and session ID.
4. Obtain each channel with `PPPIOCGCHAN`, attach it to `/dev/ppp` with
   `PPPIOCATTCHAN`, and bridge the pair with `PPPIOCBRIDGECHAN`.
5. Remove the relay tag, translate the session ID and deliver PADS to the client.

The bridge is established before the client receives PADS. The relay creates no
PPP network interfaces and does not negotiate or terminate PPP locally. The
kernel forwards session frames in either direction, including LCP, PAP, CHAP,
EAP, IPCP, IPv6CP and CCP. Unlike a userspace relay, the process opens packet
sockets only for PPPoE discovery; it never receives and retransmits session
frames in a userspace loop.

Host-Uniq, Service-Name, AC-Cookie and unknown discovery tags are preserved.
Duplicate PADS reuses the existing bridge. Failed setup releases partially
opened resources, returns an error PADS to the client and sends PADT to the AC.
The error tag fits in the space freed by the relay tag, preserving other tags
even in a full-sized PADS.

PADT is translated and forwarded before both channels are released. Channel
closure also releases its session. Interface removal, shutdown or MAC changes
stop the relay and clean up its sessions.

## Differences from RP-PPPoE

The basic `-C`, `-S` and `-n` options have the same meanings, but this is a
limited implementation rather than a command-line-compatible replacement:

- One interface pair only; no multiple `-C`/`-S` options or `-B` interfaces.
- Always foreground; no `-F` option or daemonization support.
- No `-i` idle timeout. Generic channel bridging does not expose the session
  activity information maintained by RP-PPPoE's userspace packet loop.
- Discovery already containing Relay-Session-Id is rejected; stacked relays
  are not supported.
- Discovery frames are limited to standard Ethernet frame size. MTU negotiation
  is left to endpoints; data forwarding has been tested with 1492-byte IP packets.
- No session persistence, recovery after restart or service-manager setup.

Sessions remain until PADT, channel closure, interface failure or process exit.
The random relay tag identifies the process instance; it is not an authentication
scheme. Use dedicated access links with one session manager per interface pair.

## Tests

Integration tests require root, network namespace capabilities, Python 3.12 or
newer (`os.setns`), iproute2 and the iputils `ping` command. Run them on a
disposable test system with PPPoE support:

```sh
sudo make check
```

To include interoperability with an RP-PPPoE client:

```sh
sudo env RP_PPPOE=/usr/sbin/pppoe make check
```

Without `RP_PPPOE`, only that optional interoperability case is skipped.
`PPPOE_RELAY` and `PPPOE_RELAY_PEER` can override the relay and test-peer binaries.

The 15 tests cover discovery and tag preservation, byte-for-byte PPP control/data
forwarding while the relay process is stopped with SIGSTOP, real IPv4/IPv6 ping,
RP-PPPoE client discovery, duplicate and error PADS, session collisions, capacity
recovery, partial-setup rollback, malformed discovery, spoofed peers, PADT in
both directions, descriptor reuse, channel closure, link failure and shutdown.
The duplicate cleanup test drops to UID/GID 65534 with no effective capabilities
and verifies close, disconnect and retry without disrupting the original socket.

## Reference and license

The discovery design was reviewed against
[RP-PPPoE 4.0](https://deb.debian.org/debian/pool/main/r/rp-pppoe/rp-pppoe_4.0.orig.tar.gz),
particularly `src/relay.c` and `src/relay.h`. Its relay forwards session traffic
in userspace; this independent implementation uses generic kernel PPP bridging.
The relay and its tests were initially developed alongside
[l2tp-ktest](https://github.com/katalix/l2tp-ktest).

Licensed under GPL-2.0-or-later; see [LICENSE](LICENSE).
