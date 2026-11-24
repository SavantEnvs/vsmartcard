/*
 * vpcd_peer.h — the virtual ICC side of a vpcd connection, for the harnesses
 * and the self-test. ifd-vpcd listens on a TCP port ("/dev/null:<port>") and
 * waits for a virtual ICC (vicc) to connect; everything the vicc sends is
 * untrusted. vsc_open_channel() opens the IFD channel on a per-process port,
 * vsc_peer_connect() connects as the vicc and queues the given bytes as the
 * vicc's whole reply stream, then half-closes.
 */
#ifndef VSC_VPCD_PEER_H
#define VSC_VPCD_PEER_H
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <wintypes.h>
#include <ifdhandler.h>

static unsigned short vsc_port;

/* Open IFD channel `lun` on a free port derived from the pid. */
static int vsc_open_channel(DWORD lun)
{
    char name[64];
    int i;
    if (vsc_port) {
        snprintf(name, sizeof name, "/dev/null:%u", (unsigned) vsc_port);
        if (IFDHCreateChannelByName(lun, name) == IFD_SUCCESS)
            return 1;
    }
    for (i = 0; i < 2000; i++) {
        unsigned short port = (unsigned short) (20000 + ((unsigned) getpid() * 7u + (unsigned) i * 13u) % 40000u);
        snprintf(name, sizeof name, "/dev/null:%u", (unsigned) port);
        if (IFDHCreateChannelByName(lun, name) == IFD_SUCCESS) {
            vsc_port = port;
            return 1;
        }
    }
    return 0;
}

/* Connect to the channel as the vicc, queue `len` bytes, half-close. */
static int vsc_peer_connect(const unsigned char *buf, size_t len)
{
    struct sockaddr_in sa;
    struct linger lg = { 1, 0 }; /* RST on close: no TIME_WAIT pile-up */
    size_t off = 0;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
        return -1;
    setsockopt(s, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(vsc_port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(s, (struct sockaddr *) &sa, sizeof sa) != 0) {
        close(s);
        return -1;
    }
    while (off < len) {
        ssize_t r = send(s, buf + off, len - off, MSG_NOSIGNAL);
        if (r <= 0)
            break;
        off += (size_t) r;
    }
    shutdown(s, SHUT_WR);
    return s;
}
#endif
