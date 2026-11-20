/* Apple Media Service attribute values (from the paired iPhone): CSV splitting + float parsing. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <comm/ble/kernel_le_client/ams/ams_util.h>

static bool prv_value(const char *value, uint32_t value_length, uint32_t index, void *context) {
  int32_t out;
  (void)ams_util_float_string_parse(value, value_length, 1000, &out);
  (void)ams_util_float_string_parse(value, value_length, 1, &out);
  *(uint32_t *)context += index;
  return index < 16;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > UINT32_MAX) return -1;
  /* The value is passed by length, not NUL-terminated. One guard byte follows it, as in the
   * firmware, where the value sits inside a larger GATT notification buffer: ams_util_csv_parse
   * reads value_begin[end_idx] before checking idx == end_idx, a one-byte over-read that would
   * otherwise crash every non-empty input and leave nothing else reachable. */
  char *buf = malloc(size + 1);
  memcpy(buf, data, size);
  buf[size] = '\0';
  uint32_t ctx = 0;
  (void)ams_util_csv_parse(buf, (uint32_t)size, &ctx, prv_value);
  int32_t out;
  (void)ams_util_float_string_parse(buf, (uint32_t)size, 100, &out);
  free(buf);
  return 0;
}
