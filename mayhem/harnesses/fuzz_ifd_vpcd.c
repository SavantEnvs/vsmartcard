/*
 * fuzz_ifd_vpcd — the virtual smart card reader driver ifd-vpcd
 * (virtualsmartcard/src/ifd-vpcd/ifd-vpcd.c) on top of the vpcd transport
 * (virtualsmartcard/src/vpcd/vpcd.c), driven through the PC/SC IFD handler API
 * pcscd uses (IFDHCreateChannelByName, IFDHICCPresence, IFDHPowerICC,
 * IFDHGetCapabilities, IFDHTransmitToICC, IFDHControl, IFDHCloseChannel).
 *
 * The untrusted side is the virtual ICC that connects over TCP: its replies are
 * 2-byte big-endian length-prefixed frames (ATRs, R-APDUs), parsed by
 * recvFromVICC. Input layout: byte 0 selects four extra IFD operations (2 bits
 * each); the rest is the vicc's reply stream, queued on a loopback connection
 * before the driver runs.
 *
 * State: the channel (listening socket + vicc context) is opened and closed for
 * every input, so nothing an input does survives into the next one.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "vpcd_peer.h"
#include <reader.h>

#define MAX_STREAM 32768

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const unsigned char apdu[] = { 0x00, 0xA4, 0x04, 0x00, 0x07,
        0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01, 0x00 };
    unsigned char atr[MAX_ATR_SIZE], rx[0x10000 + 2], ctl[64];
    DWORD atrlen, rxlen, ret;
    SCARD_IO_HEADER spci = { 1, 0 }, rpci;
    unsigned char ops;
    int s, i;

    if (size < 1)
        return -1;
    ops = data[0];
    data++; size--;
    if (size > MAX_STREAM)
        size = MAX_STREAM;

    if (!vsc_open_channel(0))
        abort(); /* no free loopback port: environment problem, not a finding */
    s = vsc_peer_connect(data, size);

    /* pcscd polls presence first; that is when the driver accepts the vicc */
    IFDHICCPresence(0);
    for (i = 0; i < 4; i++) {
        switch ((ops >> (2 * i)) & 3) {
        case 0:
            IFDHICCPresence(0);
            break;
        case 1:
            atrlen = sizeof atr;
            IFDHPowerICC(0, IFD_POWER_UP, atr, &atrlen);
            break;
        case 2:
            atrlen = sizeof atr;
            IFDHPowerICC(0, IFD_RESET, atr, &atrlen);
            break;
        case 3:
            atrlen = sizeof atr;
            IFDHGetCapabilities(0, TAG_IFD_ATR, &atrlen, atr);
            break;
        }
    }
    rxlen = sizeof rx;
    IFDHTransmitToICC(0, spci, (PUCHAR) apdu, sizeof apdu, rx, &rxlen, &rpci);
    rxlen = 2; /* a caller with a short buffer must be refused, not overrun */
    IFDHTransmitToICC(0, spci, (PUCHAR) apdu, 5, rx, &rxlen, &rpci);
    IFDHControl(0, CM_IOCTL_GET_FEATURE_REQUEST, NULL, 0, ctl, sizeof ctl, &ret);
    atrlen = sizeof atr;
    IFDHPowerICC(0, IFD_POWER_DOWN, atr, &atrlen);

    IFDHCloseChannel(0);
    if (s >= 0)
        close(s);
    return 0;
}
