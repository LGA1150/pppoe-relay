/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Static PPPoE endpoint for the relay's IP integration tests. */
#include <arpa/inet.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/if_ppp.h>
#include <linux/if_pppox.h>

int main(int argc, char **argv)
{
    struct sockaddr_pppox address = {.sa_family = AF_PPPOX, .sa_protocol = PX_PROTO_OE};
    struct sockaddr_storage storage = {};
    int channel, unit = -1, signo, used = 0, result = EXIT_FAILURE;
    int socket_fd = -1, channel_fd = -1, unit_fd = -1;
    sigset_t mask;
    char *end;

    if (argc != 4 || strlen(argv[1]) >= IFNAMSIZ)
        return EXIT_FAILURE;
    uint8_t *mac = address.sa_addr.pppoe.remote;
    if (sscanf(argv[2], "%2"SCNx8":%2"SCNx8":%2"SCNx8":%2"SCNx8":%2"SCNx8":%2"SCNx8"%n",
               mac, mac + 1, mac + 2, mac + 3, mac + 4, mac + 5, &used) != 6 || argv[2][used])
        return EXIT_FAILURE;
    unsigned long sid = strtoul(argv[3], &end, 10);
    if (!*argv[3] || *end || !sid || sid >= UINT16_MAX)
        return EXIT_FAILURE;
    address.sa_addr.pppoe.sid = htons(sid);
    strcpy(address.sa_addr.pppoe.dev, argv[1]);
    memcpy(&storage, &address, sizeof(address));
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);
    if (sigprocmask(SIG_BLOCK, &mask, NULL))
        goto out;
    socket_fd = socket(AF_PPPOX, SOCK_DGRAM | SOCK_CLOEXEC, PX_PROTO_OE);
    if (socket_fd < 0 || connect(socket_fd, (struct sockaddr *)&storage, sizeof(address)) ||
        ioctl(socket_fd, PPPIOCGCHAN, &channel))
        goto out;
    channel_fd = open("/dev/ppp", O_RDWR | O_CLOEXEC);
    if (channel_fd < 0 || ioctl(channel_fd, PPPIOCATTCHAN, &channel))
        goto out;
    unit_fd = open("/dev/ppp", O_RDWR | O_CLOEXEC);
    if (unit_fd < 0 || ioctl(unit_fd, PPPIOCNEWUNIT, &unit) ||
        ioctl(channel_fd, PPPIOCCONNECT, &unit))
        goto out;
    printf("ppp%d\n", unit);
    fflush(stdout);
    if (!sigwait(&mask, &signo))
        result = EXIT_SUCCESS;
out:
    if (result)
        perror("PPPoE test peer");
    if (unit_fd >= 0)
        close(unit_fd);
    if (channel_fd >= 0)
        close(channel_fd);
    if (socket_fd >= 0)
        close(socket_fd);
    return result;
}
