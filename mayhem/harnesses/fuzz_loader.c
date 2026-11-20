/* App binary loading: pbl_loader_copy + pbl_loader_relocate. In the firmware the image geometry
 * comes from the (untrusted) app binary's header, so here it does too: the first 20 bytes are the
 * five little-endian uint32 fields of struct pbl_loader_image, the rest is the app file the read
 * callback serves (bounds-checked, as in tests/subsys/loader/test_loader.c). */
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <pbl/loader/loader.h>

#define DST_SIZE 4096

static const uint8_t *s_src;
static size_t s_src_len;

static int prv_read(void *ctx, size_t offset, void *buf, size_t len) {
  if (offset > s_src_len || len > s_src_len - offset) {
    return -EIO;
  }
  memcpy(buf, s_src + offset, len);
  return 0;
}

static uint32_t prv_address(void *ctx, const void *addr) {
  return (uint32_t)((const uint8_t *)addr - (const uint8_t *)ctx);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 20) return -1;
  uint32_t f[5];
  memcpy(f, data, sizeof(f));
  const struct pbl_loader_image img = {
      .file_size = f[0], .mem_size = f[1], .header_size = f[2], .reloc_offset = f[3],
      .reloc_count = f[4]};
  s_src = data + 20;
  s_src_len = size - 20;
  const struct pbl_loader_source src = {.read = prv_read};
  uint8_t *dst = malloc(DST_SIZE);
  if (pbl_loader_copy(&img, &src, dst, DST_SIZE) >= 0) {
    (void)pbl_loader_relocate(&img, &src, dst, DST_SIZE, NULL, NULL);
    if (pbl_loader_copy(&img, &src, dst, DST_SIZE) >= 0) {
      (void)pbl_loader_relocate(&img, &src, dst, DST_SIZE, prv_address, dst);
    }
  }
  free(dst);
  return 0;
}
