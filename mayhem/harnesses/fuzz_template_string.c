/* Timeline template strings (phone-supplied pin text): parse + evaluate. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <applib/template_string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 4) return -1;
  /* first 4 bytes: the evaluation time; rest: the template */
  uint32_t t;
  memcpy(&t, data, 4);
  char *in = malloc(size - 4 + 1);
  memcpy(in, data + 4, size - 4);
  in[size - 4] = '\0';
  char out[64];
  TemplateStringEvalConditions cond = {0};
  TemplateStringVars vars = {.current_time = (time_t)t};
  TemplateStringError err = {0};
  (void)template_string_evaluate(in, out, sizeof(out), &cond, &vars, &err);
  (void)template_string_evaluate(in, NULL, 0, NULL, &vars, &err);
  free(in);
  return 0;
}
