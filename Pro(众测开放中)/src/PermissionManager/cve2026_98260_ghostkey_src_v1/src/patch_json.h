#ifndef PATCH_JSON_H_
#define PATCH_JSON_H_

#include <stdbool.h>
#include <stddef.h>

static char g_patch_json[8192] = {0};

extern char g_root_script_path[1024];

bool load_patch_json_from_file(const char *path, char *out_json, size_t out_json_size);

#endif /* PATCH_JSON_H_ */
