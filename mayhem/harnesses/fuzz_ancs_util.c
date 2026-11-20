/* Apple Notification Center Service responses (from the paired iPhone over BLE). The first byte
 * picks the response kind; the rest is the GATT data, handled as pebble/comm/ble/kernel_le_client/
 * ancs/ancs.c does: completeness check first, then attribute extraction on a complete response. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <comm/ble/kernel_le_client/ancs/ancs.h>
#include <comm/ble/kernel_le_client/ancs/ancs_types.h>
#include <comm/ble/kernel_le_client/ancs/ancs_util.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return -1;
  const uint8_t kind = data[0] & 1;
  size_t length = size - 1;
  uint8_t *buf = malloc(length ? length : 1);
  memcpy(buf, data + 1, length);
  bool error = false;
  if (kind == 0) {
    if (ancs_util_is_complete_notif_attr_response(buf, length, &error) && !error &&
        length >= sizeof(GetNotificationAttributesMsg)) {
      ANCSAttribute *attrs[NUM_FETCHED_NOTIF_ATTRIBUTES] = {0};
      (void)ancs_util_get_attr_ptrs(buf + sizeof(GetNotificationAttributesMsg),
                                    length - sizeof(GetNotificationAttributesMsg),
                                    s_fetched_notif_attributes, NUM_FETCHED_NOTIF_ATTRIBUTES,
                                    attrs, &error);
    }
  } else if (ancs_util_is_complete_app_attr_dict(buf, length, &error) && !error) {
    /* skip the NUL-terminated app id, as prv_handle_app_attributes_response does */
    const uint8_t *p = buf;
    size_t n = length;
    while (n > 0) {
      n--;
      if (*p++ == 0) break;
    }
    if (n > 0) {
      ANCSAttribute *attrs[NUM_FETCHED_APP_ATTRIBUTES] = {0};
      (void)ancs_util_get_attr_ptrs(p, n, s_fetched_app_attributes, NUM_FETCHED_APP_ATTRIBUTES,
                                    attrs, &error);
    }
  }
  free(buf);
  return 0;
}
