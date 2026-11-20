/* Pebble Draw Command (PDC) vector images and sequences from app resources: validation, then the
 * walks the renderer does over a valid one and the drawing itself (gdraw_command_image_draw /
 * gdraw_command_frame_draw into an app framebuffer, as a KinoLayer or app update_proc does). The
 * first byte picks image (even) or sequence (odd). The graphics sources linked are those of
 * upstream's test_graphics_draw_bitmap, plus the gdraw/gpath sources (mayhem/build.sh). */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <applib/applib_malloc.auto.h>
#include <applib/graphics/framebuffer.h>
#include <applib/graphics/graphics.h>
#include <applib/graphics/gdraw_command_frame.h>
#include <applib/graphics/gdraw_command_image.h>
#include <applib/graphics/gdraw_command_list.h>
#include <applib/graphics/gdraw_command_sequence.h>

/* The app's graphics context and framebuffer, reset before every input. */
extern GContext *s_app_state_get_graphics_context;
static GContext s_ctx;
static FrameBuffer s_fb;

static void prv_reset_ctx(void) {
  framebuffer_init(&s_fb, &(GSize){PBL_DISPLAY_WIDTH, PBL_DISPLAY_HEIGHT});
  graphics_context_init(&s_ctx, &s_fb, GContextInitializationMode_App);
  framebuffer_clear(&s_fb);
  s_app_state_get_graphics_context = &s_ctx;
}

static void prv_walk_list(GDrawCommandList *list) {
  if (!list) return;
  (void)gdraw_command_list_get_num_commands(list);
  (void)gdraw_command_list_get_data_size(list);
  (void)gdraw_command_list_get_num_points(list);
  uint16_t n = 0;
  GPoint *pts = gdraw_command_list_collect_points(list, false, &n);
  applib_free(pts);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return -1;
  prv_reset_ctx();
  const size_t len = size - 1;
  void *buf = malloc(len ? len : 1);
  memcpy(buf, data + 1, len);
  if ((data[0] & 1) == 0) {
    GDrawCommandImage *image = buf;
    if (gdraw_command_image_validate(image, len)) {
      (void)gdraw_command_image_get_bounds_size(image);
      prv_walk_list(gdraw_command_image_get_command_list(image));
      gdraw_command_image_draw(&s_ctx, image, GPoint(3, 5));
      graphics_context_set_antialiased(&s_ctx, false);
      gdraw_command_image_draw(&s_ctx, image, GPoint(-7, -2));
    }
  } else {
    GDrawCommandSequence *seq = buf;
    if (gdraw_command_sequence_validate(seq, len)) {
      (void)gdraw_command_sequence_get_bounds_size(seq);
      (void)gdraw_command_sequence_get_play_count(seq);
      (void)gdraw_command_sequence_get_total_duration(seq);
      (void)gdraw_command_sequence_get_data_size(seq);
      const uint32_t frames = gdraw_command_sequence_get_num_frames(seq);
      for (uint32_t i = 0; i < frames && i < 64; i++) {
        GDrawCommandFrame *f = gdraw_command_sequence_get_frame_by_index(seq, i);
        if (f) {
          prv_walk_list(gdraw_command_frame_get_command_list(f));
          gdraw_command_frame_draw(&s_ctx, seq, f, GPoint(3, 5));
        }
      }
      (void)gdraw_command_sequence_get_frame_by_elapsed(seq, 1000);
    }
  }
  free(buf);
  return 0;
}
