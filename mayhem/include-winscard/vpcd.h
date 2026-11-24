/* mayhem/include-winscard/vpcd.h — used only when compiling
 * virtualsmartcard/src/pcsclite-vpcd/winscard.c for fuzz_winscard: the real
 * header, with the compile-time default port (VPCDPORT 35963) replaced by a
 * per-process port so concurrent fuzzer processes don't collide on one port. */
#include "../../virtualsmartcard/src/vpcd/vpcd.h"
#undef VPCDPORT
extern unsigned short vsc_vpcd_port;
#define VPCDPORT vsc_vpcd_port
