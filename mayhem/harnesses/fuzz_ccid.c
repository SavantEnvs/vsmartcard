/*
 * fuzz_ccid — ccid-emulator's CCID message parser (ccid/src/ccid.c), the code
 * that handles what a USB host sends to the emulated reader: bulk-out
 * PC_to_RDR_* messages (ccid_parse_bulkout: IccPowerOn/Off, GetSlotStatus,
 * XfrBlock, GetParameters, Secure PIN verify/modify + PACE, Escape, ...) and
 * class-specific control requests (ccid_parse_control).
 *
 * The emulator relays to a real card through OpenSC; here OpenSC is given a
 * stub PC/SC provider (pcsc_stub.c, one reader + one card answering 90 00)
 * via OPENSC_CONF, so ccid_initialize() finds a reader as it does in
 * production.
 *
 * Input: a sequence of records [kind:1][len:2 little-endian][bytes:len]. Even
 * kind -> ccid_parse_bulkout(bytes, len); odd kind with len >= 8 ->
 * ccid_parse_control((struct usb_ctrlrequest *) bytes). Each record is copied
 * to its own exact-size heap buffer so over-reads are caught.
 *
 * Per-input reset: fuzz_ccid_reset() (ccid_unit.c, which compiles the
 * upstream ccid.c unchanged) disconnects and clears ccid.c's file-static card
 * handle, exactly as ccid_shutdown() does, and sets the skipfirst counter back
 * to 0. Every input thus starts from the state a freshly started emulator has
 * after ccid_initialize().
 *
 * Kept across inputs on purpose: the OpenSC context and reader from
 * ccid_initialize(), which ccid.c only reads after initialization. The stub
 * card is stateless and OpenSC is built without OpenPACE (no secure-messaging
 * state), so nothing else carries over.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ccid.h" /* ccid/src/ccid.h, found via -I$SRC/ccid/src */

void fuzz_ccid_reset(void); /* ccid_unit.c */

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    char exe[4096], conf[4096 + 64], *slash;
    const char *tmp = getenv("TMPDIR");
    ssize_t n;
    FILE *f;
    (void)argc; (void)argv;

    n = readlink("/proc/self/exe", exe, sizeof exe - 1);
    if (n <= 0)
        abort();
    exe[n] = '\0';
    slash = strrchr(exe, '/');
    if (!slash)
        abort();
    *slash = '\0';
    if (!tmp || !*tmp)
        tmp = "/tmp";
    snprintf(conf, sizeof conf, "%s/vsc_opensc_%ld.conf", tmp, (long) getpid());
    f = fopen(conf, "w");
    if (!f)
        abort();
    fprintf(f, "app default {\n  debug = 0;\n  card_drivers = default;\n"
            "  reader_driver pcsc {\n    provider_library = \"%s/libpcsc_stub.so\";\n"
            "    enable_pace = false;\n  }\n}\n", exe);
    fclose(f);
    setenv("OPENSC_CONF", conf, 1);
    if (ccid_initialize(-1, 0) < 0) {
        fprintf(stderr, "fuzz_ccid: ccid_initialize failed (stub PC/SC provider not loaded?)\n");
        abort();
    }
    unlink(conf);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    __u8 *out = NULL;

    fuzz_ccid_reset(); /* ccid.c's file-static state (see header) */

    while (size >= 3) {
        uint8_t kind = data[0];
        size_t len = (size_t) data[1] | ((size_t) data[2] << 8);
        uint8_t *rec;
        data += 3; size -= 3;
        if (len > size)
            len = size;
        rec = malloc(len ? len : 1);
        if (!rec)
            break;
        memcpy(rec, data, len);
        data += len; size -= len;
        if ((kind & 1) == 0) {
            ccid_parse_bulkout(rec, len, &out);
        } else if (len >= sizeof(struct usb_ctrlrequest)) {
            ccid_parse_control((struct usb_ctrlrequest *) rec, &out);
        }
        free(rec);
    }
    free(out);
    return 0;
}
