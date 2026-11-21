#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "patch_json.h"

char g_root_script_path[1024] = {0};

/* Read a whole file into a freshly-allocated NUL-terminated buffer.
 * Returns true on success; *out / *out_len receive the buffer and length
 * (length excludes the trailing NUL). */
static bool read_file_contents(const char *path, char **out, size_t *out_len)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        printf("open config file failed: %s errno=%d\n", path, errno);
        return false;
    }
    struct stat st;
    if (fstat(fd, &st) != 0) {
        printf("fstat config file failed: %s errno=%d\n", path, errno);
        close(fd);
        return false;
    }
    if (st.st_size <= 0) {
        printf("empty config file\n");
        close(fd);
        return false;
    }

    char *buf = (char *)malloc((size_t)st.st_size + 1);
    if (!buf) {
        printf("out of memory reading config file\n");
        close(fd);
        return false;
    }
    size_t total = 0;
    while (total < (size_t)st.st_size) {
        ssize_t n = read(fd, buf + total, (size_t)st.st_size - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            printf("read config file failed: errno=%d\n", errno);
            free(buf);
            close(fd);
            return false;
        }
        if (n == 0) break;
        total += (size_t)n;
    }
    close(fd);
    buf[total] = '\0';

    *out = buf;
    *out_len = total;
    return true;
}

/* Locate the JSON payload: the first '{' marks the start.
 * Sets *start to the opening '{' and *end to the matching closing '}'.
 * Returns true if found. */
static bool extract_json_payload(const char *text, const char **start,
                                 const char **end)
{
    const char *s = strchr(text, '{');
    if (!s) return false;

    /* Pair up braces so nested objects/arrays don't truncate the payload. */
    int depth = 0;
    const char *e = NULL;
    for (const char *q = s; *q; q++) {
        if (*q == '{') depth++;
        else if (*q == '}' && --depth == 0) {
            e = q;
            break;
        }
    }
    if (!e) return false;

    *start = s;
    *end = e;
    return true;
}

bool load_patch_json_from_file(const char *path, char *out_json,
                               size_t out_json_size)
{
    if (!out_json || out_json_size == 0) {
        printf("invalid output buffer\n");
        return false;
    }

    char *buf = NULL;
    size_t len = 0;
    if (!read_file_contents(path, &buf, &len)) {
        printf("read file failed: %s\n", path);
        return false;
    }

    const char *start = NULL;
    const char *end = NULL;
    if (!extract_json_payload(buf, &start, &end)) {
        printf("json braces not found in config file\n");
        free(buf);
        return false;
    }

    size_t json_len = (size_t)(end - start) + 1;
    if (json_len >= out_json_size) {
        printf("json too large: %zu (max %zu)\n", json_len, out_json_size - 1);
        free(buf);
        return false;
    }

    memcpy(out_json, start, json_len);
    out_json[json_len] = '\0';
    free(buf);
    return true;
}
