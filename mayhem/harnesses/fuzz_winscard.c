/*
 * fuzz_winscard — the bundled libpcsclite replacement
 * (virtualsmartcard/src/pcsclite-vpcd/winscard.c), i.e. the PC/SC API an
 * application calls (SCardEstablishContext, SCardListReaders,
 * SCardGetStatusChange, SCardConnect, SCardStatus, SCardTransmit,
 * SCardReconnect, SCardGetAttrib, SCardControl, SCardDisconnect), on top of
 * ifd-vpcd and the vpcd transport.
 *
 * Untrusted: the virtual ICC that connects to reader "Virtual PCD 00" over TCP
 * and sends 2-byte length-prefixed frames (ATRs, R-APDUs). Input layout: byte 0
 * selects four extra API calls (2 bits each), byte 1 is the length n of the
 * C-APDU the application transmits, the next n bytes are that C-APDU, and the
 * rest is the vicc's reply stream, queued on a loopback connection before the
 * library runs.
 *
 * State: the context (listening sockets, card table) is established and
 * released for every input; winscard.c's file-static card table is cleared by
 * SCardReleaseContext (release_globals), so nothing carries between inputs.
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <winscard.h>
#include <reader.h>

#define MAX_STREAM 32768

unsigned short vsc_vpcd_port; /* read by winscard.c through VPCDPORT */

static int port_free(unsigned short port)
{
    struct sockaddr_in sa;
    int one = 1, ok, s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
        return 0;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    ok = bind(s, (struct sockaddr *) &sa, sizeof sa) == 0;
    close(s);
    return ok;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    unsigned i;
    (void)argc; (void)argv;
    /* two slots: winscard.c listens on VPCDPORT and VPCDPORT+1 */
    for (i = 0; i < 4000; i++) {
        unsigned short p = (unsigned short) (20000 + ((unsigned) getpid() * 11u + i * 2u) % 40000u);
        if (port_free(p) && port_free((unsigned short) (p + 1))) {
            vsc_vpcd_port = p;
            return 0;
        }
    }
    abort(); /* no free loopback port pair: environment problem */
}

static int peer_connect(const unsigned char *buf, size_t len)
{
    struct sockaddr_in sa;
    struct linger lg = { 1, 0 };
    size_t off = 0;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
        return -1;
    setsockopt(s, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(vsc_vpcd_port);
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

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    SCARDCONTEXT ctx;
    SCARDHANDLE h = 0;
    SCARD_READERSTATE rs;
    SCARD_IO_REQUEST rpci;
    char readers[256], name[256];
    unsigned char rx[0x10000 + 2], atr[MAX_ATR_SIZE], attr[64], ctl[64];
    DWORD len, proto = 0, state, atrlen, ret;
    const unsigned char *apdu;
    size_t apdu_len;
    unsigned char ops;
    int s, i;

    if (size < 2)
        return -1;
    ops = data[0];
    apdu_len = data[1];
    data += 2; size -= 2;
    if (apdu_len > size)
        apdu_len = size;
    apdu = data;
    data += apdu_len; size -= apdu_len;
    if (size > MAX_STREAM)
        size = MAX_STREAM;

    if (SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &ctx) != SCARD_S_SUCCESS)
        return 0;
    s = peer_connect(data, size);

    len = sizeof readers;
    SCardListReaders(ctx, NULL, readers, &len);
    memset(&rs, 0, sizeof rs);
    rs.szReader = "Virtual PCD 00";
    rs.dwCurrentState = SCARD_STATE_UNAWARE;
    SCardGetStatusChange(ctx, 0, &rs, 1);
    if (SCardConnect(ctx, "Virtual PCD 00", SCARD_SHARE_SHARED,
                SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &h, &proto) == SCARD_S_SUCCESS) {
        for (i = 0; i < 4; i++) {
            switch ((ops >> (2 * i)) & 3) {
            case 0:
                len = sizeof rx;
                SCardTransmit(h, SCARD_PCI_T1, apdu, (DWORD) apdu_len, &rpci, rx, &len);
                break;
            case 1:
                SCardReconnect(h, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1, SCARD_RESET_CARD, &proto);
                break;
            case 2:
                len = sizeof name; atrlen = sizeof atr;
                SCardStatus(h, name, &len, &state, &proto, atr, &atrlen);
                break;
            case 3:
                len = sizeof attr;
                SCardGetAttrib(h, SCARD_ATTR_ATR_STRING, attr, &len);
                break;
            }
        }
        rs.dwCurrentState = rs.dwEventState;
        SCardGetStatusChange(ctx, 0, &rs, 1);
        SCardControl(h, CM_IOCTL_GET_FEATURE_REQUEST, NULL, 0, ctl, sizeof ctl, &ret);
        SCardDisconnect(h, SCARD_UNPOWER_CARD);
    }
    SCardReleaseContext(ctx);
    if (s >= 0)
        close(s);
    return 0;
}
