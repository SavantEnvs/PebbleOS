/* Language-pack (gettext MO) catalog parsing: pbl_i18n_catalog_get_info + pbl_i18n_set_catalog
 * parse the header/metadata, pbl_i18n_get* run the hash-table lookup. The catalog is the fuzz
 * input, served through the same bounds-checked read callback the unit test uses. */
#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <pbl/i18n/i18n.h>

static const uint8_t *s_data;
static size_t s_size;
static const char s_owner[] = "fuzz";

static int prv_read(void *data, uint32_t offset, void *buf, size_t length) {
  (void)data;
  if (offset > s_size || length > s_size - offset) {
    return -EINVAL;
  }
  memcpy(buf, s_data + offset, length);
  return 0;
}

static const char *const s_keys[] = {
    "Music", "Untranslated", "", "Settings", "Notifications", "Alarms",
    pbl_i18n_ctx_noop("Quiet Time", "Enabled"), pbl_i18n_ctx_noop("Notifications", "Enabled"),
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  s_data = data;
  s_size = size;
  const struct pbl_i18n_catalog catalog = {.read = prv_read, .data = NULL, .size = size};

  struct pbl_i18n_catalog_info info;
  (void)pbl_i18n_catalog_get_info(&catalog, &info);

  if (pbl_i18n_set_catalog(&catalog) == 0) {
    (void)pbl_i18n_get_locale();
    (void)pbl_i18n_get_lang_name();
    (void)pbl_i18n_get_version();
    char small[8];
    for (size_t i = 0; i < sizeof(s_keys) / sizeof(s_keys[0]); i++) {
      const char *s = pbl_i18n_get(s_keys[i], s_owner);
      (void)strlen(s);
      pbl_i18n_get_with_buffer(s_keys[i], small, sizeof(small));
      (void)pbl_i18n_get_length(s_keys[i]);
    }
    pbl_i18n_free_all(s_owner);
  }
  /* Back to the built-in English catalog: no state survives this input. */
  pbl_i18n_set_catalog(NULL);
  return 0;
}
