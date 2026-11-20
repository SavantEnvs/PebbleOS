/* PBI bitmap resources: gbitmap_init_with_resource() on an app-supplied resource, the path an
 * app's `pbi` image resources take. The resource syscalls are stubbed the way upstream's
 * tests/pebble/graphics/test_gbitmap_resource_validation.c does, except that the resource bytes
 * are the fuzz input. A loaded bitmap is then drawn into an app framebuffer with
 * graphics_draw_bitmap_in_rect(), the way an app's BitmapLayer renders it (bitblt reads the
 * pixel rows and the palette), and released with gbitmap_deinit(). The sources linked are those
 * of upstream's test_graphics_draw_bitmap, which renders `.pbi` fixtures the same way. A PNG
 * resource is decoded by gbitmap_png.c, as on the watch. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <applib/graphics/framebuffer.h>
#include <applib/graphics/gbitmap_pbi.h>
#include <applib/graphics/graphics.h>
#include <applib/graphics/gtypes.h>

static const uint8_t *s_data;
static size_t s_size;

ResAppNum sys_get_current_resource_num(void) {
  return 1;
}

const uint8_t *sys_resource_read_only_bytes(ResAppNum app_num, uint32_t resource_id,
                                            size_t *num_bytes_out) {
  return nullptr;
}

size_t sys_resource_size(ResAppNum app_num, uint32_t resource_id) {
  return s_size;
}

size_t sys_resource_load_range(ResAppNum app_num, uint32_t id, uint32_t start_offset, uint8_t *data,
                               size_t num_bytes) {
  if (start_offset > s_size) {
    return 0;
  }
  const size_t n = (num_bytes < s_size - start_offset) ? num_bytes : s_size - start_offset;
  memcpy(data, s_data + start_offset, n);
  return n;
}

/* The app's graphics context and framebuffer, as test_graphics_context_init() sets them up.
 * framebuffer_clear() and graphics_context_init() reset both before every input. */
extern GContext *s_app_state_get_graphics_context;
static GContext s_ctx;
static FrameBuffer s_fb;

static const GCompOp s_ops[] = {GCompOpAssign, GCompOpAssignInverted, GCompOpOr, GCompOpAnd,
                                GCompOpClear, GCompOpSet};

static void prv_draw(GBitmap *bitmap) {
  const GRect bounds = gbitmap_get_bounds(bitmap);
  const GBitmapFormat format = gbitmap_get_format(bitmap);
  for (int16_t y = bounds.origin.y; y < grect_get_max_y(&bounds); y++) {
    (void)gbitmap_get_data_row_info(bitmap, (uint16_t)y);
  }
  for (size_t i = 0; i < sizeof(s_ops) / sizeof(s_ops[0]); i++) {
    /* The ops other than Assign and Set are defined for 1-bit bitmaps only (the same check as
     * test_graphics_draw_bitmap's prv_gbitmap_format_and_compositing_mode_combo_is_valid). */
    if (format != GBitmapFormat1Bit && s_ops[i] != GCompOpAssign && s_ops[i] != GCompOpSet) {
      continue;
    }
    graphics_context_set_compositing_mode(&s_ctx, s_ops[i]);
    /* At the bitmap's own size, then tiled over the whole screen. */
    GRect dest = bounds;
    graphics_draw_bitmap_in_rect(&s_ctx, bitmap, &dest);
    dest = GRect(-3, -5, PBL_DISPLAY_WIDTH + 6, PBL_DISPLAY_HEIGHT + 10);
    graphics_draw_bitmap_in_rect(&s_ctx, bitmap, &dest);
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* gbitmap_init_with_data() reads the PBI header before prv_init_with_pbi_data() checks the
   * resource size, so a resource shorter than the header is read past its end (an over-read on
   * the watch too). That one bug would end every run on the first short mutation; inputs that
   * cannot hold a header are skipped so the validation and the rendering get fuzzed. An
   * empty resource returns NULL from the firmware's applib_resource_mmap_or_load(). */
  if (size < offsetof(BitmapData, data)) {
    return 0;
  }
  s_data = data;
  s_size = size;
  framebuffer_init(&s_fb, &(GSize){PBL_DISPLAY_WIDTH, PBL_DISPLAY_HEIGHT});
  graphics_context_init(&s_ctx, &s_fb, GContextInitializationMode_App);
  framebuffer_clear(&s_fb);
  s_app_state_get_graphics_context = &s_ctx;
  graphics_context_set_antialiased(&s_ctx, false);
  GBitmap bitmap;
  if (gbitmap_init_with_resource(&bitmap, 1)) {
    prv_draw(&bitmap);
    gbitmap_deinit(&bitmap);
  }
  return 0;
}
