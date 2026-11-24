/*
 * fuzz_opicc — pcsc-relay's OpenPICC RF driver (pcsc-relay/src/opicc.c).
 *
 * The OpenPICC device sends C-APDUs as text lines "LEN: xx xx ..." over a
 * serial line; pcsc-relay reads them with driver_openpicc.receive_capdu()
 * (getline + picc_decode_apdu) and answers with send_rapdu()
 * (picc_encode_rapdu). The fuzz input is the byte stream the device sends: it
 * is written to the per-process PICCDEV scratch file, the driver connects to
 * it and decodes every line through its public struct rf_driver interface.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "pcsc-relay.h"

int verbose = -1; /* pcsc-relay's global: silence RELAY_ERROR/DEBUG output */
char vsc_piccdev[4096];

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    const char *tmp = getenv("TMPDIR");
    (void)argc; (void)argv;
    if (!tmp || !*tmp)
        tmp = "/tmp";
    snprintf(vsc_piccdev, sizeof vsc_piccdev, "%s/vsc_opicc_%ld", tmp, (long)getpid());
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    driver_data_t *d = NULL;
    unsigned char *capdu = NULL, *last = NULL;
    size_t len = 0, lastlen = 0;
    volatile unsigned char sink = 0;
    FILE *f;

    if (!vsc_piccdev[0])
        LLVMFuzzerInitialize(NULL, NULL);
    f = fopen(vsc_piccdev, "w");
    if (!f)
        return 0;
    if (size)
        fwrite(data, 1, size, f);
    fclose(f);

    if (driver_openpicc.connect(&d)) {
        while (driver_openpicc.receive_capdu(d, &capdu, &len)) {
            size_t i;
            /* the relay forwards capdu[0..len) to the card: read all of it */
            for (i = 0; i < len; i++)
                sink ^= capdu[i];
            if (len) {
                unsigned char *p = realloc(last, len);
                if (!p)
                    break;
                last = p;
                memcpy(last, capdu, len);
                lastlen = len;
            }
        }
        /* echo the last C-APDU back as the R-APDU (one write: send_rapdu
         * appends to the device, which would end the read loop above) */
        if (lastlen)
            driver_openpicc.send_rapdu(d, last, lastlen);
    }
    driver_openpicc.disconnect(d);
    free(capdu);
    free(last);
    unlink(vsc_piccdev);
    (void)sink;
    return 0;
}
