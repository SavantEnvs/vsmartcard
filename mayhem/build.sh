#!/usr/bin/env bash
#
# mayhem/build.sh — build vsmartcard's fuzz harnesses and the self-test.
#
# Upstream is three autotools sub-projects whose programs also need gengetopt +
# help2man; the fuzzed code is a handful of self-contained C files, so they are
# compiled directly against mayhem/include/config.h (the values ./configure
# produces on Linux) and the PC/SC headers bundled in
# virtualsmartcard/src/pcsclite-vpcd/PCSC:
#   pcsc-relay/src/opicc.c                     OpenPICC RF driver   -> fuzz_opicc
#   virtualsmartcard/src/vpcd/{vpcd,lock}.c +
#   virtualsmartcard/src/ifd-vpcd/ifd-vpcd.c   vpcd IFD handler     -> fuzz_ifd_vpcd
#   virtualsmartcard/src/pcsclite-vpcd/{winscard,error}.c (+ the above)
#                                              PC/SC API shim       -> fuzz_winscard
#   ccid/src/{ccid,scutil}.c + static OpenSC  CCID message parser  -> fuzz_ccid
#     (ccid.c via mayhem/harnesses/ccid_unit.c, which #includes it unchanged)
# Outputs land in mayhem/out/ (gitignored); objects in mayhem/out/obj*/.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
OUT="$SRC/mayhem/out"
mkdir -p "$OUT/obj" "$OUT/obj-test"

VSC="$SRC/virtualsmartcard/src"
RELAY="$SRC/pcsc-relay/src"
INCS=(-DHAVE_CONFIG_H -I"$SRC/mayhem/include" -I"$VSC/vpcd" -I"$VSC/ifd-vpcd"
      -I"$VSC/pcsclite-vpcd/PCSC" -I"$RELAY")
PROJ_SRCS=("$RELAY/opicc.c" "$VSC/vpcd/vpcd.c" "$VSC/vpcd/lock.c" "$VSC/ifd-vpcd/ifd-vpcd.c")

# shellcheck disable=SC2206
FUZZ_CFLAGS=($SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -O1)
if [ -z "$SANITIZER_FLAGS" ]; then FUZZ_CFLAGS=($DEBUG_FLAGS -fsanitize=fuzzer-no-link -O1); fi

# 1) the project sources, instrumented (sanitizers + SanCov) for the fuzzers
objs=()
# ifd-vpcd.c: IFDHTransmitToICC (ifd-vpcd.c:457) does memcpy(RxBuffer, NULL, 0)
# whenever the vicc closes the connection: vicc_transmit -> recvFromVICC returns
# 0 and leaves rapdu NULL. Every input that ends before the vicc's last reply
# hits it, so UBSan's nonnull-attribute check would halt on nearly every input
# of fuzz_ifd_vpcd and fuzz_winscard; only that check is relaxed, for this file
# only. A non-zero copy from NULL (the 1-byte-header case) is still an ASan SEGV.
declare -A EXTRA=([ifd-vpcd]="-fno-sanitize=nonnull-attribute")
for s in "${PROJ_SRCS[@]}"; do
    b=$(basename "${s%.c}")
    o="$OUT/obj/$b.o"
    # shellcheck disable=SC2086
    "$CC" "${FUZZ_CFLAGS[@]}" ${EXTRA[$b]:-} "${INCS[@]}" -c "$s" -o "$o"
    objs+=("$o")
done
"$CC" "${FUZZ_CFLAGS[@]}" -c "$SRC/mayhem/lsan_off.c" -o "$OUT/obj/lsan_off.o"
# shellcheck disable=SC2206
"$CC" ${SANITIZER_FLAGS} $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/obj/standalone_main.o"

# 2) each harness twice: libFuzzer binary + run-once standalone reproducer
declare -A HOBJS=(
    [fuzz_opicc]="$OUT/obj/opicc.o"
    [fuzz_ifd_vpcd]="$OUT/obj/vpcd.o $OUT/obj/lock.o $OUT/obj/ifd-vpcd.o"
)
for h in fuzz_opicc fuzz_ifd_vpcd; do
    read -r -a objs <<<"${HOBJS[$h]}"
    "$CC" "${FUZZ_CFLAGS[@]}" "${INCS[@]}" -c "$SRC/mayhem/harnesses/$h.c" -o "$OUT/obj/$h.o"
    # shellcheck disable=SC2086
    "$CC" ${SANITIZER_FLAGS} $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OUT/obj/$h.o" "${objs[@]}" \
        "$OUT/obj/lsan_off.o" -lpthread -o "$OUT/$h"
    # shellcheck disable=SC2086
    "$CC" ${SANITIZER_FLAGS} $DEBUG_FLAGS -fsanitize=fuzzer-no-link "$OUT/obj/standalone_main.o" \
        "$OUT/obj/$h.o" "${objs[@]}" "$OUT/obj/lsan_off.o" -lpthread -o "$OUT/$h-standalone"
done

# 2a) the bundled libpcsclite replacement (winscard.c + error.c) over ifd-vpcd,
#     compiled with mayhem/include-winscard first so VPCDPORT is a per-process port
WS_INCS=(-I"$SRC/mayhem/include-winscard" "${INCS[@]}" -I"$VSC/pcsclite-vpcd")
for s in winscard error; do
    "$CC" "${FUZZ_CFLAGS[@]}" "${WS_INCS[@]}" -c "$VSC/pcsclite-vpcd/$s.c" -o "$OUT/obj/ws_$s.o"
done
"$CC" "${FUZZ_CFLAGS[@]}" "${WS_INCS[@]}" -c "$SRC/mayhem/harnesses/fuzz_winscard.c" -o "$OUT/obj/fuzz_winscard.o"
WS_OBJS=("$OUT/obj/ws_winscard.o" "$OUT/obj/ws_error.o" "$OUT/obj/vpcd.o" "$OUT/obj/lock.o" "$OUT/obj/ifd-vpcd.o")
# shellcheck disable=SC2086
"$CC" ${SANITIZER_FLAGS} $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OUT/obj/fuzz_winscard.o" "${WS_OBJS[@]}" \
    "$OUT/obj/lsan_off.o" -lpthread -o "$OUT/fuzz_winscard"
# shellcheck disable=SC2086
"$CC" ${SANITIZER_FLAGS} $DEBUG_FLAGS -fsanitize=fuzzer-no-link "$OUT/obj/standalone_main.o" "$OUT/obj/fuzz_winscard.o" \
    "${WS_OBJS[@]}" "$OUT/obj/lsan_off.o" -lpthread -o "$OUT/fuzz_winscard-standalone"

# 2b) ccid-emulator's CCID parser against the pinned static OpenSC (Dockerfile,
#     /opt/toolchains/deps/opensc-<commit>, uninstrumented) + a stub PC/SC
#     provider library OpenSC dlopens (environment mock, plain flags).
OSC=$(ls -d /opt/toolchains/deps/opensc-* | head -n1)
CCID_INCS=(-include "$OSC/src/config.h" -I"$OSC/src" -I"$OSC/src/src" -I"$SRC/ccid/src")
# ccid.c: get_RDR_to_PC_SlotStatus (ccid.c:375) does memcpy(out, NULL, 0) for
# every slot-status reply without a protocol data structure (IccPowerOff,
# GetSlotStatus, Abort, ...), so only nonnull-attribute is relaxed, and only for
# ccid_unit.c (= ccid.c, unchanged, plus the per-input reset hook). scutil.c and
# the harness fuzz_ccid.c get the full UBSan set.
"$CC" "${FUZZ_CFLAGS[@]}" "${CCID_INCS[@]}" -c "$SRC/ccid/src/scutil.c" -o "$OUT/obj/ccid_scutil.o"
"$CC" "${FUZZ_CFLAGS[@]}" -fno-sanitize=nonnull-attribute "${CCID_INCS[@]}" -c "$SRC/mayhem/harnesses/ccid_unit.c" -o "$OUT/obj/ccid_unit.o"
"$CC" "${FUZZ_CFLAGS[@]}" "${CCID_INCS[@]}" -c "$SRC/mayhem/harnesses/fuzz_ccid.c" -o "$OUT/obj/fuzz_ccid.o"
"$CC" -O1 -g -gdwarf-3 -fPIC -shared -I/usr/include/PCSC "$SRC/mayhem/harnesses/pcsc_stub.c" \
    -o "$OUT/libpcsc_stub.so"
CCID_LIBS=("$OSC/lib/libopensc.a" -lcrypto -lpthread -ldl)
# shellcheck disable=SC2086
"$CC" ${SANITIZER_FLAGS} $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OUT/obj/fuzz_ccid.o" \
    "$OUT/obj/ccid_unit.o" "$OUT/obj/ccid_scutil.o" "$OUT/obj/lsan_off.o" "${CCID_LIBS[@]}" -o "$OUT/fuzz_ccid"
# shellcheck disable=SC2086
"$CC" ${SANITIZER_FLAGS} $DEBUG_FLAGS -fsanitize=fuzzer-no-link "$OUT/obj/standalone_main.o" "$OUT/obj/fuzz_ccid.o" \
    "$OUT/obj/ccid_unit.o" "$OUT/obj/ccid_scutil.o" "$OUT/obj/lsan_off.o" "${CCID_LIBS[@]}" -o "$OUT/fuzz_ccid-standalone"

# 3) the self-test (known-answer tests run by mayhem/test.sh), normal flags
tobjs=()
for s in "${PROJ_SRCS[@]}" "$SRC/mayhem/tests/vsc_selftest.c"; do
    o="$OUT/obj-test/$(basename "${s%.c}").o"
    # shellcheck disable=SC2086
    "$CC" -O1 -g $COVERAGE_FLAGS "${INCS[@]}" -c "$s" -o "$o"
    tobjs+=("$o")
done
# shellcheck disable=SC2086
"$CC" $COVERAGE_FLAGS "${tobjs[@]}" -lpthread -o "$OUT/vsc_selftest"

ls -l "$OUT"/fuzz_* "$OUT/vsc_selftest"
