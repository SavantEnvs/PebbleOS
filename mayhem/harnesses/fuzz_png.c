/* PNG decoding (upng + uzlib) into a GBitmap: the path images from sideloaded apps take. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <applib/graphics/gbitmap_png.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uint8_t *buf = malloc(size ? size : 1);
  memcpy(buf, data, size);
  GBitmap *bitmap = gbitmap_create_from_png_data(buf, size);
  if (bitmap) {
    gbitmap_destroy(bitmap);
  }
  free(buf);
  return 0;
}
