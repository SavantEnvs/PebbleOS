#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# PebbleOS's fuzzable code is built for the host the way upstream builds its clar unit tests
# (cmake/modules/pbl_test.cmake): each harness links the firmware sources its unit test lists
# (mayhem/pbl_test_spec.py reads them from tests/**/CMakeLists.txt + tests/modules.cmake), the
# archive of tests/stubs/default/*.c, and lib/util. The full tests CMake project is not configured:
# it needs nanopb's protoc generator and converts thousands of image fixtures.
DEPS=/opt/toolchains/deps
dep() { local d; d=$(ls -d "$DEPS/$1"-*/src 2>/dev/null | head -1); [ -n "$d" ] || { echo "missing dep $1 under $DEPS" >&2; exit 1; }; echo "$d"; }
UPNG=$(dep upng); UZLIB=$(dep uzlib); FFF=$(dep fff); TINYMT=$(dep tinymt); NANOPB=$(dep nanopb)
export PYTHONPATH="$(dep kconfiglib)${PYTHONPATH:+:$PYTHONPATH}"
OUT="$SRC/mayhem/out"            # gitignored (mayhem/.gitignore)
OBJ="$SRC/mayhem/build"          # gitignored
mkdir -p "$OUT" "$OBJ"
spec() { python3 "$SRC/mayhem/pbl_test_spec.py" "$SRC" "$@"; }
# Map a submodule path to its pinned copy under /opt/toolchains/deps.
tp() { sed -e "s#^third_party/upng/upng/#$UPNG/#" -e "s#^third_party/uzlib/uzlib/#$UZLIB/#" \
           -e "s#^third_party/nanopb/nanopb/#$NANOPB/#" -e "s#^\([^/]\)#$SRC/\1#"; }

# The defines and include path every unit test gets (tests/CMakeLists.txt PBL_TEST_DEFINES +
# the emery platform's Kconfig values, as pbl_test.cmake's "default" platform).
COMMON_DEFS=(
  "-DCLAR_FIXTURE_PATH=\"$SRC/tests/fixtures/\"" -DCONFIG_ANALYTICS=1 -DCONFIG_LOG=1
  -DCONFIG_BOARD_PARTITIONS_DUAL_SLOT=1 -DCONFIG_PBLBOOT=1 -DCONFIG_FIRMWARE_SLOT=0
  -DCONFIG_BACKLIGHT_STANDARD_INTENSITY=50 -DCONFIG_KERNEL_NUM_PRIORITIES=5
  -DCONFIG_KERNEL_THREAD_TLS_SLOTS=2 -DCONFIG_KERNEL_STACK_ALIGN=8 -DCONFIG_KERNEL_MUTEX_LOCK_LR=1
  -DCONFIG_KERNEL_TICK_HZ=1024 -DCONFIG_KERNEL_IRQ_PRIO_KERNEL=255
  -DCONFIG_KERNEL_IRQ_PRIO_MAX_SYSCALL=191 -DCONFIG_KERNEL_STACK_GUARD_SIZE=0
  -DCONFIG_KERNEL_USER_STACK_GUARD_SIZE=0 -DCONFIG_APP_THREAD_PRIO=2 -DCONFIG_WORKER_THREAD_PRIO=1
  -DCONFIG_KERNEL_SYS_WORKQ_STACK_SIZE=4096 -DCONFIG_KERNEL_SYS_WORKQ_PRIO=1
  -DCONFIG_KERNEL_SYS_WORKQ_BOOST_PRIO=3 -DCONFIG_KERNEL_SYS_WORKQ_CALLS=30
  -DCONFIG_KERNEL_SYS_WORKQ_CALL_TIMEOUT_MS=3000 -DCONFIG_KERNEL_SYS_WORKQ_HIGH_CALLS=5
  -DCONFIG_KERNEL_SYS_WORKQ_HIGH_CALL_TIMEOUT_MS=50 -DCONFIG_KERNEL_SYS_WORKQ_HIGH_STACK_SIZE=1380
  -DCONFIG_KERNEL_SYS_WORKQ_HIGH_PRIO=4 -DCONFIG_SERVICE_BOOT_SPLASH_THREAD_STACK_SIZE=2048
  -DCONFIG_SERVICE_BOOT_SPLASH_THREAD_PRIO=3 -DCONFIG_TASK_WDT_THREAD_PRIO=4
  -DCONFIG_SERVICE_EVENTED_TIMER_MAX_PER_PROCESS=128 -DCONFIG_SERVICE_VIBE_PATTERN_MAX_STEPS=256
  -DCONFIG_SERVICE_EVENT_SERVICE_MAX_PLUGIN_SERVICES=64 -DCONFIG_SERVICE_COMPOSITOR_PARTIAL_FRAMES=1
  "-DCONFIG_BOARD_HEADER=\"board_test.h\"" "-DUPNG_CONFIG_FILE=\"upng_config.h\""
  -DUZLIB_CONF_PARANOID_CHECKS=1 -DUZLIB_CONF_LENGTHS_IN_STATE=1
  -DUNITTEST -DPLATFORM_DEFAULT=1 "-DPLATFORM_NAME=\"emery\"" -DCONFIG_SCREEN_COLOR_DEPTH_BITS=8
  -DCONFIG_APP_RAM_2X_SEGMENT_SIZE=23900 -DCONFIG_APP_RAM_3X_SEGMENT_SIZE=65536
  -DCONFIG_APP_RAM_4X_SEGMENT_SIZE=65536
)
PLATFORM_CFG=$(python3 tools/cmake/platform_config.py emery)
IFS=';' read -r -a PLATFORM_DEFS <<<"$PLATFORM_CFG"
for d in "${PLATFORM_DEFS[@]}"; do [ -n "$d" ] && COMMON_DEFS+=("-D$d"); done

includes() {  # $@ = overrides
  local o; echo "-I$SRC/include"
  for o in "$@"; do echo "-I$SRC/tests/overrides/$o"; done
  printf -- '-I%s\n' "$SRC/tests/overrides/default" "$SRC/tests/stubs" "$SRC/tests/fakes" \
    "$SRC/tests/test_includes" "$SRC/tests" "$SRC/include" "$SRC/kernel/arch/posix/include" \
    "$SRC/subsys" "$SRC/pebble" "$UZLIB/src" "$SRC/third_party/upng" "$UPNG" "$NANOPB" \
    "$TINYMT/tinymt" "$FFF" "$SRC/tests/overrides/default/resources/emery" "$SRC/include/pbl"
}

# compile_one compiles one source into <objdir> and prints the object path. Everything is
# rebuilt on every run (rlenv cleans the tree first anyway); a compiler cache, when the grader
# provides one, makes the re-run cheap.
compile_one() {  # <objdir> <src> <flags...>
  local od=$1 src=$2; shift 2
  local o="$od/$(echo "${src#$SRC/}" | sed 's#^/##; s#/#__#g').o" relax=()
  # The 8-bit 1-bit-source blitter tests source bits with `1 << i` up to i = 31, a signed shift
  # into the sign bit that Cortex-M (and clang) evaluate as intended; UBSan's shift-base check
  # would stop on every 1-bit bitmap drawn. Relaxed on this one file only (a no-op in the
  # unsanitized test build); the rest of UBSan, shift-exponent included, stays on.
  case "$src" in */applib/graphics/8_bit/bitblt_private.c) relax=(-fno-sanitize=shift-base) ;; esac
  "$CC" "$@" "${relax[@]}" -c "$src" -o "$o"
  echo "$o"
}

# Stub archive (tests/stubs/default minus fatal.c, which reports through clar).
build_stubs() {  # <tag> <flags...>
  local tag=$1; shift
  local od="$OBJ/$tag/stubs"; mkdir -p "$od"
  local objs=() s
  for s in "$SRC"/tests/stubs/default/*.c; do
    [ "$(basename "$s")" = fatal.c ] && continue
    objs+=("$(compile_one "$od" "$s" "$@")")
  done
  rm -f "$OBJ/$tag/libstubs.a"
  ar rcs "$OBJ/$tag/libstubs.a" "${objs[@]}"
  # lib/util (libutil in the CMake build), an archive too, so a test listing one of its files
  # itself does not get it twice.
  od="$OBJ/$tag/util"; mkdir -p "$od"; objs=()
  for s in "$SRC"/lib/util/*.c; do objs+=("$(compile_one "$od" "$s" "$@")"); done
  rm -f "$OBJ/$tag/libutil.a"
  ar rcs "$OBJ/$tag/libutil.a" "${objs[@]}"
}

# The objects for one unit test's source list with the given flags.
test_objs() {  # <tag> <test> <flags...>
  local tag=$1 test=$2; shift 2
  local od="$OBJ/$tag/$test"; mkdir -p "$od"
  local defs=() d s
  while read -r d; do [ -n "$d" ] && defs+=("-D$d"); done < <(spec "$test" defines)
  while read -r s; do
    [ -n "$s" ] && compile_one "$od" "$s" "$@" "${defs[@]}"
  done < <(spec "$test" sources | tp)
}

test_flags() {  # <test> -> per-test include/override flags
  local -a ov=()
  mapfile -t ov < <(spec "$1" overrides)
  includes "${ov[@]}"
  local i; while read -r i; do [ -n "$i" ] && echo "-I$SRC/$i"; done < <(spec "$1" includes)
}

# Fuzz targets: <name>:<unit test whose sources it links>[:<extra source>,...]
FUZZ_TARGETS=(
  "i18n:test_i18n"
  "dict:test_dict"
  "png:test_png"
  "vibe_score:test_vibe_score"
  "ams_util:test_ams_util"
  "template_string:test_template_string"
  "utf8:test_utf8_iterator"
  "loader:test_loader"
  "ancs_util:test_ancs_util"
  "timeline_attributes:test_attribute"
  "pdc:test_graphics_draw_bitmap:pebble/applib/graphics/gdraw_command.c,pebble/applib/graphics/gdraw_command_list.c,pebble/applib/graphics/gdraw_command_frame.c,pebble/applib/graphics/gdraw_command_image.c,pebble/applib/graphics/gdraw_command_sequence.c,pebble/applib/graphics/gpath.c"
  "pp_receive:test_receive"
  "console_frame:test_console_frame"
  "gbitmap_pbi:test_graphics_draw_bitmap:tests/fakes/fake_applib_resource.c"
)
# Unit tests test.sh runs (built with upstream's own test flags, no sanitizers).
UNIT_TESTS=(test_i18n test_dict test_vibe_score test_ams_util test_template_string test_utf8_iterator test_loader test_ancs_util test_attribute test_receive test_console_frame test_gbitmap_resource_validation)

# 1+2) Fuzz harnesses (+ standalone reproducers), project sources instrumented.
# -fsanitize=fuzzer-no-link puts SanCov on every project object and harness: without it only
# the link step sees -fsanitize=fuzzer and libFuzzer/Mayhem record no edges at all.
# -fno-sanitize=alignment: the firmware reads packed, unaligned wire data through word pointers
# (timeline attributes, vibe scores, dict tuples); Cortex-M does unaligned word loads, so those
# reports would bury the memory bugs. The rest of UBSan and ASan stay on and halting.
FUZZ_CFLAGS=(-std=c23 -O1 -fsanitize=fuzzer-no-link $SANITIZER_FLAGS -fno-sanitize=alignment $DEBUG_FLAGS -fno-common -ffp-contract=off
  -Wno-unused-command-line-argument -Wno-everything "${COMMON_DEFS[@]}")
mkdir -p "$OBJ/fuzz"
$CC "${FUZZ_CFLAGS[@]}" -c "$STANDALONE_FUZZ_MAIN" -o "$OBJ/fuzz/standalone_main.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$OBJ/fuzz/lsan_off.o"
mapfile -t BASE_INC < <(includes)
build_stubs fuzz "${FUZZ_CFLAGS[@]}" "${BASE_INC[@]}"
for entry in "${FUZZ_TARGETS[@]}"; do
  IFS=: read -r name test extra <<<"$entry"
  mapfile -t inc < <(test_flags "$test")
  mapfile -t objs < <(test_objs "fuzz" "$test" "${FUZZ_CFLAGS[@]}" "${inc[@]}")
  # gbitmap_pbi and pdc render with test_graphics_draw_bitmap's sources and add what their own
  # unit tests (test_gbitmap_resource_validation, test_gdraw_command_resources) link on top.
  IFS=, read -r -a xs <<<"${extra:-}"
  for x in "${xs[@]}"; do objs+=("$(compile_one "$OBJ/fuzz/$test" "$SRC/$x" "${FUZZ_CFLAGS[@]}" "${inc[@]}")"); done
  h="$OBJ/fuzz/$test/fuzz_$name.o"; f="$OBJ/fuzz/$test/fuzz_fatal.o"
  $CC "${FUZZ_CFLAGS[@]}" "${inc[@]}" -c "$SRC/mayhem/harnesses/fuzz_$name.c" -o "$h"
  $CC "${FUZZ_CFLAGS[@]}" "${inc[@]}" -c "$SRC/mayhem/harnesses/fuzz_fatal.c" -o "$f"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$h" "$f" "${objs[@]}" \
    "$OBJ/fuzz/lsan_off.o" "$OBJ/fuzz/libstubs.a" "$OBJ/fuzz/libutil.a" -lm -o "$OUT/fuzz_$name"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$OBJ/fuzz/standalone_main.o" "$h" "$f" "${objs[@]}" \
    "$OBJ/fuzz/lsan_off.o" "$OBJ/fuzz/libstubs.a" "$OBJ/fuzz/libutil.a" -lm -o "$OUT/fuzz_$name-standalone"
done

# 3) The unit tests, with upstream's own flags (PBL_TEST_C_FLAGS minus -Werror) + clar.
TEST_CFLAGS=(-std=c23 -Wall -g3 -O0 -fdata-sections -ffunction-sections -fno-common
  -ffp-contract=off -fexcess-precision=standard -Wno-unused-command-line-argument $COVERAGE_FLAGS
  "${COMMON_DEFS[@]}")
build_stubs test "${TEST_CFLAGS[@]}" "${BASE_INC[@]}"
for test in "${UNIT_TESTS[@]}"; do
  mapfile -t inc < <(test_flags "$test")
  mapfile -t objs < <(test_objs "test" "$test" "${TEST_CFLAGS[@]}" "${inc[@]}")
  td="$OBJ/test/$test/clar"; mkdir -p "$td"
  python3 tools/clar/clar.py --file="$SRC/$(spec "$test" source)" --clar-path=tools/clar "$td" >/dev/null
  fatal=$(compile_one "$OBJ/test/$test" "$SRC/tests/stubs/default/fatal.c" "${TEST_CFLAGS[@]}" "${inc[@]}" -I"$td")
  $CC "${TEST_CFLAGS[@]}" -I"$td" "${inc[@]}" "$SRC/$(spec "$test" source)" "$td/clar_main.c" \
    "$fatal" "${objs[@]}" "$OBJ/test/libstubs.a" "$OBJ/test/libutil.a" -lm -o "$OUT/$test"
done
echo "build.sh: built ${#FUZZ_TARGETS[@]} fuzz targets and ${#UNIT_TESTS[@]} unit tests into $OUT"
