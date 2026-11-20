/* Timeline / notification attribute + action deserialization (phone-supplied over BlobDB). The
 * first two bytes are the attribute and action counts, which in the firmware come from the same
 * untrusted item header; the rest is the serialized payload. Same sequence as
 * tests/pebble/services/timeline/test_attribute.c: parse sizes, allocate, init, deserialize. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <pbl/kernel/malloc.h>
#include <pbl/services/timeline/attribute.h>
#include <pbl/services/timeline/attributes_actions.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2) return -1;
  const uint8_t num_attributes = data[0];
  const uint8_t num_actions = data[1];
  const size_t payload_size = size - 2;
  uint8_t *payload = malloc(payload_size ? payload_size : 1);
  memcpy(payload, data + 2, payload_size);

  uint8_t attributes_per_action[256];
  size_t string_alloc_size = 0;
  if (attributes_actions_parse_serial_data(num_attributes, num_actions, payload, payload_size,
                                           &string_alloc_size, attributes_per_action)) {
    const size_t buffer_size = attributes_actions_get_required_buffer_size(
        num_attributes, num_actions, attributes_per_action, string_alloc_size);
    uint8_t *buffer = pbl_zalloc(buffer_size ? buffer_size : 1);
    uint8_t *const buffer_end = buffer + buffer_size;
    uint8_t *cursor = buffer;
    AttributeList attr_list = {0};
    TimelineItemActionGroup action_group = {0};
    attributes_actions_init(&attr_list, &action_group, &cursor, num_attributes, num_actions,
                            attributes_per_action);
    if (attributes_actions_deserialize(&attr_list, &action_group, cursor, buffer_end, payload,
                                       payload_size)) {
      (void)attribute_get_string(&attr_list, AttributeIdTitle, NULL);
      (void)attribute_get_string(&attr_list, AttributeIdBody, NULL);
      (void)attributes_actions_get_serialized_payload_size(&attr_list, &action_group);
      (void)attributes_actions_get_buffer_size(&attr_list, &action_group);
    }
    pbl_free(buffer);
  }
  free(payload);
  return 0;
}
