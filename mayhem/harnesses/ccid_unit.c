/*
 * ccid_unit.c — ccid/src/ccid.c compiled as-is (upstream file untouched) plus
 * one hook for fuzz_ccid.c: fuzz_ccid_reset() resets ccid.c's file-static
 * per-session state at the start of every input.
 *
 *   - card: PC_to_RDR_IccPowerOn connects it and IccPowerOff never
 *     disconnects it; it is disconnected and cleared exactly as
 *     ccid_shutdown() does.
 *   - skipfirst: get_bStatus skips presence detection for its first 11 calls;
 *     set back to its start value 0.
 *
 * This is a separate translation unit so that only upstream code gets the
 * nonnull-attribute relaxation build.sh applies to it (see build.sh); the
 * harness itself (fuzz_ccid.c) is compiled with the full UBSan set.
 */
#include "ccid.c" /* ccid/src/ccid.c, found via -I$SRC/ccid/src */

void fuzz_ccid_reset(void);

void fuzz_ccid_reset(void)
{
    if (card) {
        sc_sm_stop(card);
        sc_disconnect_card(card);
        card = NULL;
    }
    skipfirst = 0;
}
