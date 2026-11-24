/*
 * vsc_selftest — known-answer tests for the C code the fuzz targets reach
 * (the repo has no C test suite of its own):
 *   - pcsc-relay OpenPICC driver: decoding "LEN: xx .." C-APDU lines, rejecting
 *     incomplete ones, encoding R-APDUs;
 *   - ifd-vpcd + vpcd: the IFD handler talking to a scripted virtual ICC, with
 *     the exact frames vpcd sends to the vicc and the ATR/R-APDU it returns.
 * Prints one "PASS <name>"/"FAIL <name>" line per check; exit 1 on any FAIL.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "pcsc-relay.h"
#include "../harnesses/vpcd_peer.h"
#include <reader.h>

int verbose = -1;
char vsc_piccdev[4096];
static int failures;

static void check(int ok, const char *name)
{
    printf("%s %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok)
        failures++;
}

static void test_opicc(void)
{
    static const unsigned char want[] = { 0x00, 0xA4, 0x04, 0x00, 0x00 };
    static const unsigned char rapdu[] = { 0x90, 0x00 };
    driver_data_t *d = NULL;
    unsigned char *capdu = NULL;
    size_t len = 99;
    char out[256];
    FILE *f;
    int r;

    snprintf(vsc_piccdev, sizeof vsc_piccdev, "%s/vsc_selftest_%ld",
            getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp", (long) getpid());
    f = fopen(vsc_piccdev, "w");
    fputs("05: 00 A4 04 00 00\n\nRESET\n2: 100 00\n", f);
    fclose(f);

    check(driver_openpicc.connect(&d) == 1, "opicc_connect");
    r = driver_openpicc.receive_capdu(d, &capdu, &len);
    check(r == 1 && len == sizeof want && capdu && memcmp(capdu, want, len) == 0,
            "opicc_decode_capdu");
    r = driver_openpicc.receive_capdu(d, &capdu, &len);
    check(r == 1 && len == 0, "opicc_empty_line");
    len = 99;
    r = driver_openpicc.receive_capdu(d, &capdu, &len);
    check(r == 1 && len == 0, "opicc_line_without_length_ignored");
    r = driver_openpicc.receive_capdu(d, &capdu, &len);
    check(r == 0, "opicc_reject_byte_above_ff");
    check(driver_openpicc.send_rapdu(d, rapdu, sizeof rapdu) == 1, "opicc_send_rapdu");
    driver_openpicc.disconnect(d);
    free(capdu);

    /* the R-APDU line is appended to the device: "<hex len>:..." */
    memset(out, 0, sizeof out);
    f = fopen(vsc_piccdev, "r");
    if (f) {
        char line[128];
        while (fgets(line, sizeof line, f))
            strncpy(out, line, sizeof out - 1);
        fclose(f);
    }
    check(strncmp(out, "2:", 2) == 0, "opicc_encode_rapdu_length");
    unlink(vsc_piccdev);
}

static void test_ifd_vpcd(void)
{
    static const unsigned char vicc[] = {
        0x00, 0x04, 0x3B, 0x8A, 0x80, 0x01,     /* ATR for the presence poll */
        0x00, 0x04, 0x3B, 0x8A, 0x80, 0x01,     /* ATR after power up */
        0x00, 0x02, 0x90, 0x00,                 /* R-APDU */
        0x00, 0x05, 0x01, 0x02, 0x03, 0x90, 0x00 /* R-APDU too big for caller */
    };
    static const unsigned char want_sent[] = {
        0x00, 0x01, 0x04,                       /* ATR request */
        0x00, 0x01, 0x01,                       /* power on */
        0x00, 0x01, 0x04,                       /* ATR request */
        0x00, 0x04, 0x00, 0xA4, 0x04, 0x00,     /* the C-APDU */
        0x00, 0x04, 0x00, 0xB0, 0x00, 0x00,     /* the second C-APDU */
    };
    static const unsigned char apdu[] = { 0x00, 0xA4, 0x04, 0x00 };
    static const unsigned char apdu2[] = { 0x00, 0xB0, 0x00, 0x00 };
    unsigned char atr[MAX_ATR_SIZE], rx[64], sent[64];
    DWORD atrlen = sizeof atr, rxlen = sizeof rx, ret = 0;
    SCARD_IO_HEADER spci = { 1, 0 }, rpci = { 0, 0 };
    PCSC_TLV_STRUCTURE tlv;
    size_t got = 0;
    int s;

    check(vsc_open_channel(0), "ifd_create_channel");
    s = vsc_peer_connect(vicc, sizeof vicc);
    check(s >= 0, "ifd_vicc_connect");
    check(IFDHICCPresence(0) == IFD_ICC_PRESENT, "ifd_icc_present");
    check(IFDHPowerICC(0, IFD_POWER_UP, atr, &atrlen) == IFD_SUCCESS
            && atrlen == 4 && memcmp(atr, vicc + 2, 4) == 0, "ifd_power_up_atr");
    check(IFDHTransmitToICC(0, spci, (PUCHAR) apdu, sizeof apdu, rx, &rxlen, &rpci) == IFD_SUCCESS
            && rxlen == 2 && rx[0] == 0x90 && rx[1] == 0x00 && rpci.Protocol == 1,
            "ifd_transmit_rapdu");
    rxlen = 2;
    check(IFDHTransmitToICC(0, spci, (PUCHAR) apdu2, sizeof apdu2, rx, &rxlen, &rpci) != IFD_SUCCESS
            && rxlen == 0, "ifd_transmit_short_buffer_refused");
    check(IFDHControl(0, CM_IOCTL_GET_FEATURE_REQUEST, NULL, 0, (PUCHAR) &tlv, sizeof tlv, &ret) == IFD_SUCCESS
            && ret == sizeof tlv && tlv.tag == FEATURE_GET_TLV_PROPERTIES && tlv.length == 4,
            "ifd_control_feature_request");
    atrlen = 1;
    check(IFDHGetCapabilities(0, TAG_IFD_SLOTS_NUMBER, &atrlen, atr) == IFD_SUCCESS
            && atrlen == 1 && atr[0] == 2, "ifd_slots_number");
    check(IFDHCloseChannel(0) == IFD_SUCCESS, "ifd_close_channel");
    if (s >= 0) {
        ssize_t r;
        while (got < sizeof sent && (r = recv(s, sent + got, sizeof sent - got, 0)) > 0)
            got += (size_t) r;
        close(s);
    }
    check(got == sizeof want_sent && memcmp(sent, want_sent, got) == 0, "vpcd_frames_sent_to_vicc");
}

int main(void)
{
    test_opicc();
    test_ifd_vpcd();
    printf("SUMMARY failures=%d\n", failures);
    return failures ? 1 : 0;
}
