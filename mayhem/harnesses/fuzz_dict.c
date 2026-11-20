/* AppMessage dictionary (Tuple list) handling, as received from the phone or another app: the
 * buffer is parsed (dict_read_*, dict_find), and the parsed tuples go through the calls an
 * AppMessage receiver / AppSync makes on them: re-serialization (dict_calc_buffer_size_from_tuplets,
 * dict_serialize_tuplets*, dict_write_*) and dict_merge of one received dictionary into another. */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <applib/dict.h>

#define MAX_TUPLETS 64

static volatile uint32_t s_sink;

static void prv_key_updated(const uint32_t key, const Tuple *new_tuple, const Tuple *old_tuple,
                            void *context) {
  s_sink += key + new_tuple->length + old_tuple->length;
}

static void prv_serialized(const uint8_t *const data, const uint16_t size, void *context) {
  s_sink += size + (size ? data[size - 1] : 0);
}

/* Writes tuplets[from], tuplets[from + step], ... into a fresh dictionary in buf. */
static uint32_t prv_write_subset(DictionaryIterator *it, uint8_t *buf, uint32_t cap,
                                 const Tuplet *tuplets, int n, int from, int step) {
  if (dict_write_begin(it, buf, (uint16_t)cap) != DICT_OK) {
    return 0;
  }
  for (int i = from; i < n; i += step) {
    if (dict_write_tuplet(it, &tuplets[i]) != DICT_OK) {
      break;
    }
  }
  return dict_write_end(it);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > UINT16_MAX) {
    return -1; /* dict_read_begin_from_buffer takes a uint16_t size */
  }
  /* The message sits in a larger receive buffer, as an AppMessage inbox does on the watch. The
   * slack keeps get_safe_cursor's known header over-read (dict.c:140: it reads a Tuple's length
   * before checking that a whole header fits, so every 2-7 byte input crashes) inside the
   * allocation, so fuzzing gets past it to the round-trip, merge and writer code. The parsed
   * length is still `size`; any read past the slack is still reported by ASan. */
  uint8_t *buf = calloc(1, size + sizeof(Tuple));
  memcpy(buf, data, size);
  DictionaryIterator it;
  Tuplet tuplets[MAX_TUPLETS];
  int n = 0;
  for (Tuple *t = dict_read_begin_from_buffer(&it, buf, (uint16_t)size); t; t = dict_read_next(&it)) {
    s_sink += t->key + t->type + t->length;
    /* Tuples are packed and unaligned (as on the watch): read the value bytes, not the union. */
    const uint8_t *v = (const uint8_t *)t + offsetof(Tuple, value);
    if (n == MAX_TUPLETS) {
      continue;
    }
    /* Tuplet's union members are const: build each one with an initializer. */
    switch (t->type) {
      case TUPLE_CSTRING:
      case TUPLE_BYTE_ARRAY: {
        for (uint16_t i = 0; i < t->length; i++) {
          s_sink += v[i];
        }
        const Tuplet tl = {.type = t->type, .key = t->key, .bytes = {.data = v, .length = t->length}};
        memcpy(&tuplets[n++], &tl, sizeof(tl));
        break;
      }
      case TUPLE_INT:
      case TUPLE_UINT: {
        /* Integers are 1, 2 or 4 bytes wide (dict_write_int); a Tuplet stores at most 4. */
        if (t->length != 4 && t->length != 2 && t->length != 1) {
          break;
        }
        uint32_t x = 0;
        memcpy(&x, v, t->length);
        s_sink += x;
        const Tuplet tl = {.type = t->type, .key = t->key,
                           .integer = {.storage = x, .width = t->length}};
        memcpy(&tuplets[n++], &tl, sizeof(tl));
        break;
      }
    }
  }
  s_sink += dict_size(&it);
  if (dict_read_begin_from_buffer(&it, buf, (uint16_t)size)) {
    (void)dict_find(&it, 1);
    (void)dict_find(&it, 0xFFFFFFFF);
    if (n > 0) {
      (void)dict_find(&it, tuplets[n - 1].key);
    }
  }

  /* Re-serialize the parsed tuples; reading the result back must give the same tuples. */
  uint32_t need = dict_calc_buffer_size_from_tuplets(tuplets, (uint8_t)n);
  uint8_t *out = malloc(need);
  uint32_t out_size = need;
  if (dict_serialize_tuplets_to_buffer(tuplets, (uint8_t)n, out, &out_size) != DICT_OK ||
      out_size != need) {
    fprintf(stderr, "dict: serializing %d tuplets into %u bytes failed\n", n, need);
    abort();
  }
  DictionaryIterator rt;
  int m = 0;
  for (Tuple *t = dict_read_begin_from_buffer(&rt, out, (uint16_t)out_size); t;
       t = dict_read_next(&rt), m++) {
    if (m >= n || t->key != tuplets[m].key || t->type != tuplets[m].type) {
      fprintf(stderr, "dict: round trip differs at tuple %d\n", m);
      abort();
    }
  }
  if (m != n) {
    fprintf(stderr, "dict: round trip gave %d of %d tuples\n", m, n);
    abort();
  }
  (void)dict_serialize_tuplets(prv_serialized, NULL, tuplets, (uint8_t)n);
  free(out);

  /* Merge a dictionary of the odd tuples into one of the even tuples, as AppSync does with an
   * incoming message. The destination is sized from the input, so it can be too small. */
  uint32_t cap = need + (size ? data[0] : 0);
  if (cap > UINT16_MAX) {
    cap = UINT16_MAX;
  }
  uint8_t *dest_buf = malloc(cap);
  uint8_t *new_buf = malloc(cap);
  DictionaryIterator dest, upd;
  prv_write_subset(&dest, dest_buf, cap, tuplets, n, 0, 2);
  uint32_t new_len = prv_write_subset(&upd, new_buf, cap, tuplets, n, 1, 2);
  if (new_len && dict_read_begin_from_buffer(&upd, new_buf, (uint16_t)new_len) != NULL) {
    uint32_t dest_len = need / 2 + (size > 1 ? data[1] : 0);
    if (dest_len > cap) {
      dest_len = cap;
    }
    const bool existing_only = size > 2 && (data[2] & 1);
    if (dict_merge(&dest, &dest_len, &upd, existing_only, prv_key_updated, NULL) == DICT_OK) {
      DictionaryIterator chk;
      for (Tuple *t = dict_read_begin_from_buffer(&chk, dest_buf, (uint16_t)dest_len); t;
           t = dict_read_next(&chk)) {
        s_sink += t->key;
      }
    }
  }
  free(dest_buf);
  free(new_buf);

  /* The typed writers into a small fixed buffer (runs out of storage on larger inputs). */
  uint8_t small[64];
  DictionaryIterator w;
  if (dict_write_begin(&w, small, sizeof(small)) == DICT_OK) {
    for (int i = 0; i < n; i++) {
      DictionaryResult r;
      const Tuplet *tl = &tuplets[i];
      if (tl->type == TUPLE_CSTRING) {
        char str[32];
        size_t l = tl->cstring.length < sizeof(str) - 1 ? tl->cstring.length : sizeof(str) - 1;
        memcpy(str, tl->cstring.data, l);
        str[l] = '\0';
        r = dict_write_cstring(&w, tl->key, str);
      } else if (tl->type == TUPLE_BYTE_ARRAY) {
        r = dict_write_data(&w, tl->key, tl->bytes.data, tl->bytes.length);
      } else if (tl->integer.width == 1) {
        r = tl->type == TUPLE_INT ? dict_write_int8(&w, tl->key, (int8_t)tl->integer.storage)
                                  : dict_write_uint8(&w, tl->key, (uint8_t)tl->integer.storage);
      } else if (tl->integer.width == 2) {
        r = tl->type == TUPLE_INT ? dict_write_int16(&w, tl->key, (int16_t)tl->integer.storage)
                                  : dict_write_uint16(&w, tl->key, (uint16_t)tl->integer.storage);
      } else {
        r = tl->type == TUPLE_INT ? dict_write_int32(&w, tl->key, (int32_t)tl->integer.storage)
                                  : dict_write_uint32(&w, tl->key, tl->integer.storage);
      }
      if (r != DICT_OK) {
        break;
      }
    }
    s_sink += dict_write_end(&w);
  }
  free(buf);
  return 0;
}
