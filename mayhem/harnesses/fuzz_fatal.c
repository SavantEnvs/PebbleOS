/* Fatal-path stubs for the fuzz harnesses: upstream's tests/stubs/default/fatal.c reports through
 * clar, which a fuzzer has no use for. A firmware assert or panic aborts, so it is reported as a
 * crash with the asserting file/line. */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <pbl/kernel/compiler.h>
#include <pbl/kernel/fatal.h>

[[noreturn]] void pbl_panic_at(const char *filename, int line_number, const char *message, ...) {
  fprintf(stderr, "*** PBL PANIC: %s:%d %s\n", filename, line_number, message ? message : "");
  abort();
}

[[noreturn]] void util_assertion_failed(const char *filename, int line) {
  pbl_panic_at(filename, line, "util assertion failed");
}

[[noreturn]] void pbl_panic_bare_at(const char *filename, int line_number) {
  pbl_panic_at(filename, line_number, NULL);
}

[[noreturn]] void pbl_fatal_error_handler(uintptr_t lr) {
  fprintf(stderr, "*** PBL FATAL ERROR lr=%#lx\n", (unsigned long)lr);
  abort();
}
