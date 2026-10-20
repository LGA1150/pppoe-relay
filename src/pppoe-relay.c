/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * PPPoE relay: discovery and session management in userspace, bidirectional
 * PPP forwarding in ppp_generic via PPPIOCBRIDGECHAN. No PPP units are created.
 *
 * Discovery follows RP-PPPoE's relay design: add a Relay-Session-Id to PADI,
 * swap its return address on PADO/PADR, remove it on PADS, and translate session
 * IDs. This is an independent implementation, limited to one interface pair.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_ppp.h>
#include <linux/if_pppox.h>

#ifndef PPPIOCBRIDGECHAN
#define PPPIOCBRIDGECHAN _IOW('t', 53, int)
#endif
#ifndef PPPIOCUNBRIDGECHAN
#define PPPIOCUNBRIDGECHAN _IO('t', 52)
#endif

#define CLIENT 0
#define SERVER 1
#define HEADER_LEN (ETH_HLEN + 6)
#define MAX_PAYLOAD (ETH_DATA_LEN - 6)
#define TAG_RELAY 0x0110
#define TAG_GENERIC_ERROR 0x0203
#define TOKEN_LEN 8
#define RELAY_LEN (TOKEN_LEN + 1 + ETH_ALEN)
#define RELAY_TAG_LEN (4 + RELAY_LEN)
#define MAX_SESSIONS 65534

struct interface {
    char name[IFNAMSIZ];
    int fd, index;
    uint8_t mac[ETH_ALEN];
};

struct endpoint {
    int socket_fd, channel_fd, channel;
    uint16_t sid;
    uint8_t mac[ETH_ALEN];
};

struct session {
    bool used;
    uint64_t generation;
    struct endpoint end[2];
};

/* Access wire fields as bytes to avoid unaligned loads and bitfield layouts. */
struct packet {
    uint8_t data[ETH_FRAME_LEN];
    size_t length;
};

struct tags {
    size_t relay;
    bool error;
};

static struct interface interfaces[2] = {{.fd = -1}, {.fd = -1}};
static struct session *sessions;
static unsigned int max_sessions = 128;
static uint8_t instance[TOKEN_LEN];
static uint64_t generation;
static bool verbose;
static const uint8_t broadcast[ETH_ALEN] = {255, 255, 255, 255, 255, 255};

static uint16_t get16(const uint8_t *p)
{
    return ((uint16_t)p[0] << 8) | p[1];
}

static void put16(uint8_t *p, uint16_t value)
{
    p[0] = value >> 8;
    p[1] = value;
}

static bool unicast(const uint8_t *mac)
{
    static const uint8_t zero[ETH_ALEN];
    return !(mac[0] & 1) && memcmp(mac, zero, ETH_ALEN);
}

static void set_length(struct packet *packet, size_t payload)
{
    put16(packet->data + 18, payload);
    packet->length = HEADER_LEN + payload;
}

static int send_packet(int side, struct packet *packet, const uint8_t *peer)
{
    struct interface *iface = &interfaces[side];
    ssize_t sent;

    memcpy(packet->data, peer, ETH_ALEN);
    memcpy(packet->data + ETH_ALEN, iface->mac, ETH_ALEN);
    do {
        sent = send(iface->fd, packet->data, packet->length, MSG_DONTWAIT);
    } while (sent < 0 && errno == EINTR);
    if (sent == (ssize_t)packet->length)
        return 0;
    if (sent >= 0)
        errno = EIO;
    fprintf(stderr, "send discovery on %s: %s\n", iface->name, strerror(errno));
    return -1;
}

static bool parse_tags(const struct packet *packet, struct tags *tags)
{
    size_t pos = HEADER_LEN;

    *tags = (struct tags){.relay = SIZE_MAX};
    while (pos < packet->length) {
        if (packet->length - pos < 4)
            return false;
        uint16_t type = get16(packet->data + pos);
        size_t length = get16(packet->data + pos + 2);
        if (length > packet->length - pos - 4)
            return false;
        if (!type)
            return !length && pos + 4 == packet->length;
        if (type == TAG_RELAY) {
            if (tags->relay != SIZE_MAX)
                return false;
            tags->relay = pos;
        }
        if (type >= 0x0201 && type <= 0x0203)
            tags->error = true;
        pos += 4 + length;
    }
    return true;
}

static void relay_tag(uint8_t *tag, int return_side, const uint8_t *peer)
{
    put16(tag, TAG_RELAY);
    put16(tag + 2, RELAY_LEN);
    memcpy(tag + 4, instance, TOKEN_LEN);
    tag[4 + TOKEN_LEN] = return_side;
    memcpy(tag + 4 + TOKEN_LEN + 1, peer, ETH_ALEN);
}

static bool relay_peer(const struct packet *packet, const struct tags *tags,
                       int return_side, uint8_t *peer)
{
    if (tags->relay == SIZE_MAX)
        return false;
    const uint8_t *tag = packet->data + tags->relay;
    if (get16(tag + 2) != RELAY_LEN ||
        memcmp(tag + 4, instance, TOKEN_LEN) ||
        tag[4 + TOKEN_LEN] != return_side)
        return false;
    memcpy(peer, tag + 4 + TOKEN_LEN + 1, ETH_ALEN);
    return unicast(peer) &&
           memcmp(peer, interfaces[return_side].mac, ETH_ALEN);
}

static void remove_relay(struct packet *packet, size_t pos)
{
    memmove(packet->data + pos, packet->data + pos + RELAY_TAG_LEN,
            packet->length - pos - RELAY_TAG_LEN);
    set_length(packet, packet->length - HEADER_LEN - RELAY_TAG_LEN);
}

static void send_padt(int side, const struct endpoint *end)
{
    struct packet packet = {.length = HEADER_LEN};
    put16(packet.data + 12, ETH_P_PPP_DISC);
    packet.data[14] = 0x11;
    packet.data[15] = PADT_CODE;
    put16(packet.data + 16, end->sid);
    (void)send_packet(side, &packet, end->mac);
}

static void close_endpoint(struct endpoint *end)
{
    if (end->channel_fd >= 0) {
        (void)ioctl(end->channel_fd, PPPIOCUNBRIDGECHAN);
        close(end->channel_fd);
    }
    if (end->socket_fd >= 0)
        close(end->socket_fd);
    end->channel_fd = end->socket_fd = -1;
}

static void destroy_session(struct session *session, bool notify, const char *why)
{
    if (notify) {
        send_padt(CLIENT, &session->end[CLIENT]);
        send_padt(SERVER, &session->end[SERVER]);
    }
    fprintf(stderr, "session closed client_sid=%u server_sid=%u: %s\n",
            session->end[CLIENT].sid, session->end[SERVER].sid, why);
    close_endpoint(&session->end[CLIENT]);
    close_endpoint(&session->end[SERVER]);
    session->used = false;
}

static struct session *find_session(int side, const uint8_t *mac, uint16_t sid)
{
    for (unsigned int i = 0; i < max_sessions; i++) {
        struct session *session = &sessions[i];
        if (session->used && session->end[side].sid == sid &&
            !memcmp(session->end[side].mac, mac, ETH_ALEN))
            return session;
    }
    return NULL;
}

static int open_endpoint(int side, struct endpoint *end)
{
    struct sockaddr_pppox address = {
        .sa_family = AF_PPPOX,
        .sa_protocol = PX_PROTO_OE,
    };
    struct sockaddr_storage storage = {};

    address.sa_addr.pppoe.sid = htons(end->sid);
    memcpy(address.sa_addr.pppoe.remote, end->mac, ETH_ALEN);
    memcpy(address.sa_addr.pppoe.dev, interfaces[side].name, IFNAMSIZ);
    memcpy(&storage, &address, sizeof(address));
    end->socket_fd = socket(AF_PPPOX, SOCK_DGRAM | SOCK_CLOEXEC, PX_PROTO_OE);
    if (end->socket_fd < 0 ||
        connect(end->socket_fd, (struct sockaddr *)&storage, sizeof(address)) < 0 ||
        ioctl(end->socket_fd, PPPIOCGCHAN, &end->channel) < 0)
        return -1;
    end->channel_fd = open("/dev/ppp", O_RDWR | O_CLOEXEC);
    if (end->channel_fd < 0 ||
        ioctl(end->channel_fd, PPPIOCATTCHAN, &end->channel) < 0)
        return -1;
    return 0;
}

static struct session *create_session(const uint8_t *client_mac,
                                      const uint8_t *server_mac, uint16_t sid)
{
    struct session *session = NULL;
    unsigned int slot;

    for (slot = 0; slot < max_sessions; slot++) {
        if (!sessions[slot].used) {
            session = &sessions[slot];
            break;
        }
    }
    if (!session) {
        errno = ENOSPC;
        return NULL;
    }
    memset(session, 0, sizeof(*session));
    for (int side = 0; side < 2; side++)
        session->end[side].socket_fd = session->end[side].channel_fd = -1;
    session->end[CLIENT].sid = slot + 1;
    session->end[SERVER].sid = sid;
    memcpy(session->end[CLIENT].mac, client_mac, ETH_ALEN);
    memcpy(session->end[SERVER].mac, server_mac, ETH_ALEN);
    if (open_endpoint(CLIENT, &session->end[CLIENT]) < 0 ||
        open_endpoint(SERVER, &session->end[SERVER]) < 0 ||
        ioctl(session->end[CLIENT].channel_fd, PPPIOCBRIDGECHAN,
              &session->end[SERVER].channel) < 0) {
        int error = errno;
        close_endpoint(&session->end[CLIENT]);
        close_endpoint(&session->end[SERVER]);
        errno = error;
        return NULL;
    }
    session->generation = ++generation;
    session->used = true;
    fprintf(stderr, "session opened client_sid=%u server_sid=%u channels=%d/%d\n",
            session->end[CLIENT].sid, sid,
            session->end[CLIENT].channel, session->end[SERVER].channel);
    return session;
}

/* Keep every AC tag, including Host-Uniq, even in a maximum-size PADS.
 * The error fits in the space freed by our relay tag; prepend it before EOL. */
static void setup_error(struct packet *packet, const struct tags *tags,
                        const uint8_t *client_mac, const uint8_t *server_mac)
{
    static const char message[] = "Bridge failed";
    _Static_assert(4 + sizeof(message) - 1 <= RELAY_TAG_LEN, "error must fit in relay tag space");
    struct endpoint end = {.sid = get16(packet->data + 16)};
    memcpy(end.mac, server_mac, ETH_ALEN);
    send_padt(SERVER, &end);
    remove_relay(packet, tags->relay);
    size_t length = packet->length - HEADER_LEN;
    size_t extra = 4 + sizeof(message) - 1;
    memmove(packet->data + HEADER_LEN + extra, packet->data + HEADER_LEN, length);
    put16(packet->data + HEADER_LEN, TAG_GENERIC_ERROR);
    put16(packet->data + HEADER_LEN + 2, sizeof(message) - 1);
    memcpy(packet->data + HEADER_LEN + 4, message, sizeof(message) - 1);
    set_length(packet, length + extra);
    put16(packet->data + 16, 0);
    (void)send_packet(CLIENT, packet, client_mac);
}

static void discovery(int side, struct packet *packet, const struct tags *tags)
{
    uint8_t source[ETH_ALEN], peer[ETH_ALEN];
    uint8_t code = packet->data[15];
    uint16_t sid = get16(packet->data + 16);

    memcpy(source, packet->data + ETH_ALEN, ETH_ALEN);
    if (code == PADI_CODE) {
        if (side != CLIENT || sid || memcmp(packet->data, broadcast, ETH_ALEN) ||
            tags->relay != SIZE_MAX ||
            packet->length + RELAY_TAG_LEN > sizeof(packet->data))
            return;
        size_t length = packet->length - HEADER_LEN;
        memmove(packet->data + HEADER_LEN + RELAY_TAG_LEN,
                packet->data + HEADER_LEN, length);
        relay_tag(packet->data + HEADER_LEN, CLIENT, source);
        set_length(packet, length + RELAY_TAG_LEN);
        (void)send_packet(SERVER, packet, broadcast);
        return;
    }
    if (memcmp(packet->data, interfaces[side].mac, ETH_ALEN))
        return;
    if (code == PADT_CODE) {
        struct session *session = find_session(side, source, sid);
        if (!session)
            return;
        struct endpoint *other = &session->end[1 - side];
        put16(packet->data + 16, other->sid);
        (void)send_packet(1 - side, packet, other->mac);
        destroy_session(session, false, "PADT");
        return;
    }
    if (code == PADO_CODE || code == PADR_CODE) {
        int return_side = code == PADO_CODE ? CLIENT : SERVER;
        if (side == return_side || sid ||
            !relay_peer(packet, tags, return_side, peer))
            return;
        relay_tag(packet->data + tags->relay, side, source);
        (void)send_packet(return_side, packet, peer);
        return;
    }
    if (code != PADS_CODE || side != SERVER || sid == UINT16_MAX ||
        !relay_peer(packet, tags, CLIENT, peer) || (sid && tags->error))
        return;
    struct session *session = NULL;
    bool created = false;
    if (sid) {
        session = find_session(SERVER, source, sid);
        if (session && memcmp(session->end[CLIENT].mac, peer, ETH_ALEN)) {
            /* An AC reused a live tuple for a different client. Never attach
             * that client to the existing bridge or tear its owner down. */
            return;
        }
        if (!session) {
            session = create_session(peer, source, sid);
            if (!session) {
                fprintf(stderr, "bridge setup failed: %s\n", strerror(errno));
                setup_error(packet, tags, peer, source);
                return;
            }
            created = true;
        }
        put16(packet->data + 16, session->end[CLIENT].sid);
    }
    remove_relay(packet, tags->relay);
    /* The bridge exists before the client sees PADS and starts PPP. */
    if (send_packet(CLIENT, packet, peer) < 0 && created)
        destroy_session(session, true, "PADS delivery failed");
}

static void receive_discovery(int side)
{
    struct sockaddr_ll address;
    socklen_t address_len = sizeof(address);
    struct packet packet;
    struct tags tags;
    ssize_t received = recvfrom(interfaces[side].fd, packet.data, sizeof(packet.data),
                                MSG_TRUNC | MSG_DONTWAIT,
                                (struct sockaddr *)&address, &address_len);
    if (received < 0) {
        if (errno != EAGAIN && errno != EINTR)
            fprintf(stderr, "receive discovery: %s\n", strerror(errno));
        return;
    }
    if (address.sll_pkttype == PACKET_OUTGOING || received < HEADER_LEN ||
        received > (ssize_t)sizeof(packet.data) || packet.data[14] != 0x11 ||
        get16(packet.data + 12) != ETH_P_PPP_DISC ||
        !unicast(packet.data + ETH_ALEN) ||
        !memcmp(packet.data + ETH_ALEN, interfaces[side].mac, ETH_ALEN))
        return;
    packet.length = HEADER_LEN + get16(packet.data + 18);
    if (packet.length > (size_t)received || !parse_tags(&packet, &tags)) {
        if (verbose)
            fprintf(stderr, "ignored malformed discovery on %s\n", interfaces[side].name);
        return;
    }
    discovery(side, &packet, &tags);
}

static int interface_info(struct interface *iface, bool initial)
{
    struct ifreq request = {};
    memcpy(request.ifr_name, iface->name, IFNAMSIZ);
    if (ioctl(iface->fd, SIOCGIFINDEX, &request) < 0)
        return -1;
    if (initial)
        iface->index = request.ifr_ifindex;
    else if (iface->index != request.ifr_ifindex)
        goto changed;
    if (ioctl(iface->fd, SIOCGIFHWADDR, &request) < 0)
        return -1;
    if (request.ifr_hwaddr.sa_family != ARPHRD_ETHER)
        goto changed;
    if (initial)
        memcpy(iface->mac, request.ifr_hwaddr.sa_data, ETH_ALEN);
    else if (memcmp(iface->mac, request.ifr_hwaddr.sa_data, ETH_ALEN))
        goto changed;
    if (ioctl(iface->fd, SIOCGIFMTU, &request) < 0)
        return -1;
    if (request.ifr_mtu < ETH_DATA_LEN)
        goto changed;
    if (ioctl(iface->fd, SIOCGIFFLAGS, &request) < 0)
        return -1;
    if (!(request.ifr_flags & IFF_UP))
        goto changed;
    return 0;
changed:
    errno = ENETDOWN;
    return -1;
}

static int open_interface(struct interface *iface)
{
    struct sockaddr_ll address = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_PPP_DISC),
    };
    iface->fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK,
                       htons(ETH_P_PPP_DISC));
    if (iface->fd < 0 || interface_info(iface, true) < 0)
        return -1;
    address.sll_ifindex = iface->index;
    return bind(iface->fd, (struct sockaddr *)&address, sizeof(address));
}

static int relay_loop(int signal_fd)
{
    size_t count = 3 + 2 * (size_t)max_sessions;
    struct pollfd *fds = calloc(count, sizeof(*fds));
    uint64_t *snapshot = calloc(max_sessions, sizeof(*snapshot));
    int result = 1;

    if (!fds || !snapshot)
        goto out;
    fprintf(stderr, "READY client=%s server=%s max_sessions=%u\n",
            interfaces[CLIENT].name, interfaces[SERVER].name, max_sessions);
    for (;;) {
        fds[0] = (struct pollfd){.fd = interfaces[0].fd, .events = POLLIN};
        fds[1] = (struct pollfd){.fd = interfaces[1].fd, .events = POLLIN};
        fds[2] = (struct pollfd){.fd = signal_fd, .events = POLLIN};
        for (unsigned int i = 0; i < max_sessions; i++) {
            snapshot[i] = sessions[i].generation;
            for (int side = 0; side < 2; side++)
                fds[3 + i * 2 + side] = (struct pollfd){
                    .fd = sessions[i].used ? sessions[i].end[side].channel_fd : -1,
                    /* Only watch HUP/ERR; never consume any PPP frames. */
                    .events = 0,
                };
        }
        int ready = poll(fds, count, 1000);
        if (ready < 0) {
            if (errno == EINTR)
                continue;
            perror("poll");
            break;
        }
        if (fds[2].revents) {
            result = 0;
            break;
        }
        bool failed = false;
        for (int side = 0; side < 2; side++) {
            if (interface_info(&interfaces[side], false) < 0 ||
                (fds[side].revents & (POLLERR | POLLHUP | POLLNVAL))) {
                fprintf(stderr, "interface %s unavailable or changed\n", interfaces[side].name);
                failed = true;
                break;
            }
            if (fds[side].revents & POLLIN)
                receive_discovery(side);
        }
        if (failed)
            break;
        for (unsigned int i = 0; i < max_sessions; i++) {
            if (sessions[i].used && sessions[i].generation == snapshot[i] &&
                ((fds[3 + i * 2].revents | fds[4 + i * 2].revents) &
                 (POLLHUP | POLLERR | POLLNVAL)))
                destroy_session(&sessions[i], true, "channel closed");
        }
    }
out:
    free(snapshot);
    free(fds);
    return result;
}

static void usage(const char *name)
{
    fprintf(stderr, "Usage: %s -C client-interface -S server-interface [-n sessions] [-v]\n"
            "Foreground PPPoE relay. Discovery/PADT use userspace; PPP frames use\n"
            "PPPIOCBRIDGECHAN. Requires CAP_NET_RAW, CAP_NET_ADMIN and /dev/ppp.\n"
            "One interface pair, MTU >= 1500, no stacked relays or idle timeout.\n"
            "-n: maximum active sessions (default 128); -v: log malformed discovery.\n", name);
}

int main(int argc, char **argv)
{
    int option, signal_fd = -1, result = EXIT_FAILURE;
    struct rlimit limit;
    sigset_t mask;

    while ((option = getopt(argc, argv, "hC:S:n:v")) != -1) {
        switch (option) {
        case 'C': case 'S': {
            int side = option == 'C' ? CLIENT : SERVER;
            if (!*optarg || strlen(optarg) >= IFNAMSIZ || interfaces[side].name[0]) {
                usage(argv[0]);
                return EXIT_FAILURE;
            }
            strcpy(interfaces[side].name, optarg);
            break;
        }
        case 'n': {
            char *end;
            errno = 0;
            unsigned long value = strtoul(optarg, &end, 10);
            if (errno || !*optarg || *end || !value || value > MAX_SESSIONS) {
                fprintf(stderr, "invalid session limit: %s\n", optarg);
                return EXIT_FAILURE;
            }
            max_sessions = value;
            break;
        }
        case 'v': verbose = true; break;
        case 'h': usage(argv[0]); return EXIT_SUCCESS;
        default: usage(argv[0]); return EXIT_FAILURE;
        }
    }
    if (optind != argc || !interfaces[0].name[0] || !interfaces[1].name[0] ||
        !strcmp(interfaces[0].name, interfaces[1].name)) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    if (getrlimit(RLIMIT_NOFILE, &limit) < 0 ||
        limit.rlim_cur < 4 * (rlim_t)max_sessions + 16) {
        fprintf(stderr, "session limit requires RLIMIT_NOFILE >= %lu\n",
                4UL * max_sessions + 16);
        return EXIT_FAILURE;
    }
    for (size_t done = 0; done < sizeof(instance);) {
        ssize_t n = getrandom(instance + done, sizeof(instance) - done, 0);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            perror("getrandom");
            return EXIT_FAILURE;
        }
        done += n;
    }
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0 ||
        (signal_fd = signalfd(-1, &mask, SFD_CLOEXEC)) < 0) {
        perror("signalfd");
        goto out;
    }
    sessions = calloc(max_sessions, sizeof(*sessions));
    if (!sessions) {
        perror("calloc sessions");
        goto out;
    }
    for (int side = 0; side < 2; side++) {
        if (open_interface(&interfaces[side]) < 0) {
            fprintf(stderr, "open %s: %s\n", interfaces[side].name, strerror(errno));
            goto out;
        }
    }
    if (interfaces[0].index == interfaces[1].index) {
        fprintf(stderr, "client and server interfaces must be different\n");
        goto out;
    }
    result = relay_loop(signal_fd);
out:
    if (sessions) {
        for (unsigned int i = 0; i < max_sessions; i++)
            if (sessions[i].used)
                destroy_session(&sessions[i], true, "relay stopping");
        free(sessions);
    }
    for (int side = 0; side < 2; side++)
        if (interfaces[side].fd >= 0)
            close(interfaces[side].fd);
    if (signal_fd >= 0)
        close(signal_fd);
    return result;
}
