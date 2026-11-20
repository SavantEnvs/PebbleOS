/* Vibe score resources (app-supplied vibration patterns): vibe_score_validate (what
 * vibe_score_create_with_resource runs on the loaded resource), then the timing walks and the
 * playback that turns notes into vibe steps. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <pbl/drivers/vibe.h>
#include <pbl/services/vibes/vibe_score.h>

/* The environment the unit test (tests/pebble/services/test_vibe_score.c) stubs too. */
void sys_vibe_pattern_trigger_start(void) {}
ResAppNum sys_get_current_resource_num(void) { return 0; }
const uint8_t *sys_resource_read_only_bytes(ResAppNum app_num, uint32_t resource_id,
                                            size_t *num_bytes_out) {
  return NULL;
}
const struct pbl_vibe *const VIBE = NULL;
int8_t pbl_vibe_get_braking_strength(const struct pbl_vibe *vibe) { return -100; }
static volatile uint32_t s_steps;
bool sys_vibe_pattern_enqueue_step_raw(uint32_t duration_ms, int32_t strength) {
  s_steps += duration_ms + (uint32_t)strength;
  return true;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > UINT32_MAX) return -1;
  VibeScore *score = malloc(size ? size : 1);
  memcpy(score, data, size);
  if (vibe_score_validate(score, (uint32_t)size)) {
    (void)vibe_score_get_duration_ms(score);
    (void)vibe_score_get_repeat_delay_ms(score);
    vibe_score_do_vibe(score);
  }
  free(score);
  return 0;
}
