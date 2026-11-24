/*
 * pcsc_stub.c — a minimal PC/SC provider library (libpcsclite replacement) for
 * the ccid harness: one reader ("Mayhem Stub Reader 00 00") with one card
 * (fixed ATR, T=1) that answers every APDU with 90 00. OpenSC loads it through
 * its documented `reader_driver pcsc { provider_library = ...; }` setting, so
 * ccid-emulator gets a reader and a card without any hardware. It is
 * stateless: every call returns the same answer, so nothing carries between
 * fuzz inputs here.
 */
#include <string.h>
#include <PCSC/winscard.h>

static const char reader_name[] = "Mayhem Stub Reader 00 00";
static const unsigned char atr[] = { 0x3B, 0x80, 0x80, 0x01, 0x01 };

LONG SCardEstablishContext(DWORD s, LPCVOID a, LPCVOID b, LPSCARDCONTEXT c)
{ (void)s; (void)a; (void)b; if (c) *c = 1; return SCARD_S_SUCCESS; }
LONG SCardReleaseContext(SCARDCONTEXT c) { (void)c; return SCARD_S_SUCCESS; }
LONG SCardIsValidContext(SCARDCONTEXT c) { (void)c; return SCARD_S_SUCCESS; }

LONG SCardListReaders(SCARDCONTEXT c, LPCSTR g, LPSTR r, LPDWORD n)
{
    DWORD need = sizeof reader_name + 1; /* multi-string: name\0\0 */
    (void)c; (void)g;
    if (!n)
        return SCARD_E_INVALID_PARAMETER;
    if (!r) { *n = need; return SCARD_S_SUCCESS; }
    if (*n < need) { *n = need; return SCARD_E_INSUFFICIENT_BUFFER; }
    memcpy(r, reader_name, sizeof reader_name);
    r[sizeof reader_name] = '\0';
    *n = need;
    return SCARD_S_SUCCESS;
}

LONG SCardGetStatusChange(SCARDCONTEXT c, DWORD t, SCARD_READERSTATE *st, DWORD n)
{
    DWORD i;
    (void)c; (void)t;
    for (i = 0; i < n; i++) {
        if (st[i].szReader && strcmp(st[i].szReader, reader_name) == 0) {
            st[i].dwEventState = SCARD_STATE_PRESENT
                | ((st[i].dwCurrentState & SCARD_STATE_PRESENT) ? 0 : SCARD_STATE_CHANGED);
            st[i].cbAtr = sizeof atr;
            memcpy(st[i].rgbAtr, atr, sizeof atr);
        } else {
            st[i].dwEventState = st[i].dwCurrentState & ~SCARD_STATE_CHANGED;
        }
    }
    return t == 0 ? SCARD_S_SUCCESS : SCARD_E_TIMEOUT;
}

LONG SCardConnect(SCARDCONTEXT c, LPCSTR r, DWORD m, DWORD p, LPSCARDHANDLE h, LPDWORD ap)
{
    (void)c; (void)r; (void)m; (void)p;
    if (h) *h = 2;
    if (ap) *ap = SCARD_PROTOCOL_T1;
    return SCARD_S_SUCCESS;
}
LONG SCardReconnect(SCARDHANDLE h, DWORD m, DWORD p, DWORD i, LPDWORD ap)
{ (void)h; (void)m; (void)p; (void)i; if (ap) *ap = SCARD_PROTOCOL_T1; return SCARD_S_SUCCESS; }
LONG SCardDisconnect(SCARDHANDLE h, DWORD d) { (void)h; (void)d; return SCARD_S_SUCCESS; }
LONG SCardBeginTransaction(SCARDHANDLE h) { (void)h; return SCARD_S_SUCCESS; }
LONG SCardEndTransaction(SCARDHANDLE h, DWORD d) { (void)h; (void)d; return SCARD_S_SUCCESS; }
LONG SCardCancel(SCARDCONTEXT c) { (void)c; return SCARD_S_SUCCESS; }

LONG SCardStatus(SCARDHANDLE h, LPSTR name, LPDWORD nlen, LPDWORD state,
        LPDWORD proto, LPBYTE a, LPDWORD alen)
{
    (void)h;
    if (nlen) {
        if (name && *nlen >= sizeof reader_name)
            memcpy(name, reader_name, sizeof reader_name);
        *nlen = sizeof reader_name;
    }
    if (state) *state = SCARD_SPECIFIC;
    if (proto) *proto = SCARD_PROTOCOL_T1;
    if (alen) {
        if (a && *alen >= sizeof atr)
            memcpy(a, atr, sizeof atr);
        *alen = sizeof atr;
    }
    return SCARD_S_SUCCESS;
}

LONG SCardTransmit(SCARDHANDLE h, const SCARD_IO_REQUEST *sp, LPCBYTE s, DWORD sl,
        SCARD_IO_REQUEST *rp, LPBYTE r, LPDWORD rl)
{
    (void)h; (void)sp; (void)s; (void)sl; (void)rp;
    if (!r || !rl || *rl < 2)
        return SCARD_E_INSUFFICIENT_BUFFER;
    r[0] = 0x90; r[1] = 0x00; *rl = 2;
    return SCARD_S_SUCCESS;
}

LONG SCardControl(SCARDHANDLE h, DWORD code, LPCVOID s, DWORD sl, LPVOID r, DWORD rl, LPDWORD ret)
{ (void)h; (void)code; (void)s; (void)sl; (void)r; (void)rl; if (ret) *ret = 0; return SCARD_E_UNSUPPORTED_FEATURE; }
LONG SCardGetAttrib(SCARDHANDLE h, DWORD id, LPBYTE a, LPDWORD al)
{ (void)h; (void)id; (void)a; if (al) *al = 0; return SCARD_E_UNSUPPORTED_FEATURE; }
LONG SCardSetAttrib(SCARDHANDLE h, DWORD id, LPCBYTE a, DWORD al)
{ (void)h; (void)id; (void)a; (void)al; return SCARD_E_UNSUPPORTED_FEATURE; }
