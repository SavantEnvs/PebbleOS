/* Serial console framing as received over the UART: pbl_console__frame_input_from_isr() is fed
 * every received byte from the ISR, splits plain text from ESC _ <channel> <base64> ESC \ frames,
 * and queues prv_process_frame (base64 decode, CRC check, dispatch to the Pebble Protocol console
 * transport) or prv_process_ack on the system work queue. Same sources and fakes as
 * tests/subsys/console/test_console_frame.c.
 *
 * Input: byte 0 picks when the queued work runs (bit 0 set: after every byte, as when the work
 * queue keeps up; clear: only at the end, so later frames arrive while one is pending); bit 1 set
 * makes the work queue report full. The rest is the received byte stream.
 *
 * frame.c keeps the receiver state in statics. Each input starts from the same state: a newline
 * returns the state machine to text from any state, and a valid sequence-0 frame on an unused
 * channel resets the last sequence number, as the host does on connect. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pbl/console/console.h>
#include <pbl/crc/crc.h>
#include <pbl/kernel/work.h>
#include <pbl/util/base64.h>

#include <console/console_private.h>

static volatile uint32_t s_sink;
static bool s_queue_full;
static pbl_work_call_fn_t s_task_cb;
static pbl_work_call_fn_t s_high_cb;

void pbl_console_lock(void) {}
void pbl_console_unlock(void) {}
void pbl_console_putchar(char c) { s_sink += (uint8_t)c; }
void pbl_console_flush(void) {}

bool pbl_sys_work_call_from_isr(pbl_work_call_fn_t cb, void *data) {
  if (s_queue_full) {
    return false;
  }
  s_task_cb = cb;
  return true;
}

void pbl_sys_work_call_high_from_isr(pbl_work_call_fn_t cb, void *data) { s_high_cb = cb; }

/* The transport takes at most PBL_CONSOLE_FRAME_MTU bytes (console.h). */
static uint8_t s_pp[PBL_CONSOLE_FRAME_MTU];
void pbl_pp_console_receive(const void *data, size_t len) {
  if (len > sizeof(s_pp)) {
    fprintf(stderr, "console frame: %zu-byte payload over the %d-byte MTU\n", len,
            PBL_CONSOLE_FRAME_MTU);
    abort();
  }
  memcpy(s_pp, data, len);
  s_sink += len;
}

void pbl_pp_console_ack(uint8_t seq) { s_sink += seq; }
void pbl_console__imaging_handle_frame(const void *data, size_t len) { s_sink += len; }

static void prv_text_input(char c) { s_sink += (uint8_t)c; }

static void prv_run_work(void) {
  if (s_high_cb != NULL) {
    pbl_work_call_fn_t cb = s_high_cb;
    s_high_cb = NULL;
    cb(NULL);
  }
  if (s_task_cb != NULL) {
    pbl_work_call_fn_t cb = s_task_cb;
    s_task_cb = NULL;
    cb(NULL);
  }
}

static void prv_feed(const char *data, size_t len, bool run_each) {
  for (size_t i = 0; i < len; i++) {
    pbl_console__frame_input_from_isr(data[i], prv_text_input);
    if (run_each) {
      prv_run_work();
    }
  }
}

static void prv_reset(void) {
  /* ESC _ 'R' base64(seq 0 | crc) ESC \ */
  const char channel = 'R';
  uint8_t raw[1 + sizeof(uint32_t)] = {0};
  const uint32_t crc = pbl_crc32(pbl_crc32(0, &channel, 1), raw, 1);
  memcpy(&raw[1], &crc, sizeof(crc));
  char frame[32] = "\n\x1b_R";
  size_t len = 4;
  len += pbl_base64_encode(&frame[len], sizeof(frame) - len, raw, sizeof(raw));
  frame[len++] = 0x1b;
  frame[len++] = '\\';
  s_queue_full = false;
  prv_feed(frame, len, true);
  prv_run_work();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) {
    return -1;
  }
  prv_reset();
  const bool run_each = data[0] & 1;
  s_queue_full = data[0] & 2;
  prv_feed((const char *)data + 1, size - 1, run_each);
  s_queue_full = false;
  prv_run_work();
  return 0;
}
