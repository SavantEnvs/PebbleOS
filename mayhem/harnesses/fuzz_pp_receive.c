/* Pebble Protocol framing as received from the phone (BLE/serial transports all feed
 * pbl_pp_session_receive): length/endpoint header parsing, reassembly across transport chunks,
 * endpoint lookup + access check, receiver prepare/write/finish and the meta-error path.
 * Modelled on tests/subsys/pp/test_receive.c (same sources and endpoints). The input is a list
 * of transport chunks, each [len byte][len bytes]. A receiver that is written more bytes than it
 * was prepared for aborts: that is a framing bug in the session. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pp_private.h"

#include <pbl/kernel/work.h>
#include <pbl/pp/endpoint.h>
#include <pbl/pp/protocol.h>
#include <pbl/pp/transport.h>

#include <kernel/event_loop.h>
#include <kernel/events.h>

/* KernelMain / SysWorkq callbacks: queued and run after each chunk, like the test's fake. */
#define MAX_CB 64
static struct { void (*cb)(void *); void *data; } s_cbs[MAX_CB];
static int s_num_cbs;
static void prv_queue(void (*cb)(void *), void *data) {
  if (s_num_cbs == MAX_CB) abort();
  s_cbs[s_num_cbs].cb = cb;
  s_cbs[s_num_cbs].data = data;
  s_num_cbs++;
}
static void prv_run_cbs(void) {
  for (int i = 0; i < s_num_cbs; i++) s_cbs[i].cb(s_cbs[i].data);
  s_num_cbs = 0;
}
bool pbl_sys_work_call(pbl_work_call_fn_t cb, void *data) { prv_queue(cb, data); return true; }
bool pbl_sys_work_call_from_isr(pbl_work_call_fn_t cb, void *data) { prv_queue(cb, data); return true; }
bool pbl_sys_work_try_call(pbl_work_call_fn_t cb, void *data) { prv_queue(cb, data); return true; }
size_t pbl_sys_work_num_free(void) { return MAX_CB - s_num_cbs; }
void launcher_task_add_callback(CallbackEventCallback callback, void *data) { prv_queue(callback, data); }
bool launcher_task_is_current_task(void) { return false; }
void event_put(PebbleEvent *event) {}
void pbl_pp__version_request(struct pbl_pp_session *session) {}
static volatile unsigned s_meta_errors;
void pbl_pp__meta_send_error(struct pbl_pp_session *session, enum pbl_pp__meta_error error,
                             uint16_t endpoint_id) {
  s_meta_errors += (unsigned)error + endpoint_id;
}

/* One receiver for every endpoint: tracks prepared vs written length. */
static struct { size_t prepared; size_t written; uint8_t *buf; int open; } s_rx;
static struct pbl_pp_receiver *prv_prepare(struct pbl_pp_session *session,
                                           const struct pbl_pp_endpoint *endpoint, size_t length) {
  if (s_rx.open) {
    fprintf(stderr, "receiver prepared twice without finish/cleanup\n");
    abort();
  }
  s_rx.prepared = length;
  s_rx.written = 0;
  s_rx.buf = malloc(length ? length : 1);
  s_rx.open = 1;
  return (struct pbl_pp_receiver *)&s_rx;
}
static void prv_write(struct pbl_pp_receiver *receiver, const uint8_t *data, size_t length) {
  if (!s_rx.open || length > s_rx.prepared - s_rx.written) {
    fprintf(stderr, "receiver write of %zu past prepared %zu (written %zu)\n", length,
            s_rx.prepared, s_rx.written);
    abort();
  }
  memcpy(s_rx.buf + s_rx.written, data, length);
  s_rx.written += length;
}
static void prv_done(struct pbl_pp_receiver *receiver) {
  free(s_rx.buf);
  s_rx.buf = NULL;
  s_rx.open = 0;
}
static const struct pbl_pp_receiver_api s_receiver = {
    .prepare = prv_prepare, .write = prv_write, .finish = prv_done, .cleanup = prv_done};
const struct pbl_pp_receiver_api pbl_pp_kernel_receiver = {
    .prepare = prv_prepare, .write = prv_write, .finish = prv_done, .cleanup = prv_done};

PBL_PP_ENDPOINT_DEFINE_RECEIVER(0x0001, PBL_PP_ACCESS_PRIVATE, s_receiver);
PBL_PP_ENDPOINT_DEFINE_RECEIVER(0x0002, PBL_PP_ACCESS_PUBLIC, s_receiver);
PBL_PP_ENDPOINT_DEFINE_RECEIVER(0x0003, PBL_PP_ACCESS_ANY, s_receiver);
static void prv_handler(struct pbl_pp_session *session, const uint8_t *data, size_t length) {}
PBL_PP_ENDPOINT_DEFINE(0x0004, PBL_PP_ACCESS_ANY, prv_handler);

static void prv_send_next(struct pbl_pp_session *session) {}
static const struct pbl_pp_transport s_transport = {.name = "fuzz", .send_next = prv_send_next};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct pbl_pp_session *session =
      pbl_pp_session_open(&s_transport, PBL_PP_DESTINATION_SYSTEM, NULL);
  if (!session) return 0;
  prv_run_cbs();
  size_t pos = 0;
  while (pos < size) {
    size_t n = data[pos++];
    if (n > size - pos) n = size - pos;
    pbl_pp_session_receive(session, data + pos, n);
    pos += n;
    prv_run_cbs();
  }
  pbl_pp_session_close(session);
  prv_run_cbs();
  if (s_rx.open) prv_done(NULL); /* a close mid-message must have cleaned up; reset regardless */
  return 0;
}
