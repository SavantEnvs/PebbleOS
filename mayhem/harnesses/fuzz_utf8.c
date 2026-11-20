/* UTF-8 validation/decoding applied to all phone-supplied text. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <applib/graphics/utf8.h>

static bool prv_cp(int index, Codepoint codepoint, void *context) {
  *(uint32_t *)context += codepoint + index;
  return true;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *in = malloc(size + 1);
  memcpy(in, data, size);
  in[size] = '\0';
  uint32_t sink = 0;
  if (utf8_is_valid_string(in)) {
    (void)utf8_each_codepoint(in, prv_cp, &sink);
    utf8_t *p = (utf8_t *)in;
    while (*p) {
      utf8_t *next = NULL;
      sink += utf8_peek_codepoint(p, &next);
      if (!next || next <= p) break;
      p = next;
    }
    /* documented for valid UTF-8 (callers validate phone text first) */
    char out[16];
    (void)utf8_truncate_with_ellipsis(in, out, sizeof(out));
    (void)utf8_get_size_truncate(in, 7);
  }
  (void)sink;
  free(in);
  return 0;
}
