#ifndef EXEC_CMDLINE_UTILS_H
#define EXEC_CMDLINE_UTILS_H

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/wait.h>

extern char **environ;

struct cmdline_argv {
    char *buf;
    char **argv;
    size_t argc;
};

static void free_cmdline_argv(cmdline_argv &out) {
    if (out.argv) {
        free(out.argv);
        out.argv = NULL;
    }
    if (out.buf) {
        free(out.buf);
        out.buf = NULL;
    }
    out.argc = 0;
}

static bool build_cmdline_argv(const char *cmdline, cmdline_argv &out) {
    out.buf = NULL;
    out.argv = NULL;
    out.argc = 0;

    if (cmdline == NULL || *cmdline == '\0') {
        return false;
    }

    char *buf = strdup(cmdline);
    if (!buf) {
        return false;
    }

    size_t cap = 8;
    char **argv = (char **)calloc(cap + 1, sizeof(char *));
    if (!argv) {
        free(buf);
        return false;
    }

    size_t argc = 0;
    char *p = buf;

    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
            ++p;
        }
        if (*p == '\0') {
            break;
        }

        if (argc >= cap) {
            size_t new_cap = cap * 2;
            char **new_argv = (char **)realloc(argv, (new_cap + 1) * sizeof(char *));
            if (!new_argv) {
                free(argv);
                free(buf);
                return false;
            }
            argv = new_argv;
            memset(argv + cap, 0, (new_cap + 1 - cap) * sizeof(char *));
            cap = new_cap;
        }

        char *dst = p;
        argv[argc++] = dst;

        if (*p == '"' || *p == '\'') {
            char quote = *p;
            ++p;
            argv[argc - 1] = dst = p;

            while (*p && *p != quote) {
                *dst++ = *p++;
            }
            
            if (*p == quote) {
                ++p;
            }
            *dst = '\0';
        } else {
            while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') {
                ++p;
            }
            if (*p) {
                *p = '\0';
                ++p;
            }
        }
    }

    if (argc == 0) {
        free(argv);
        free(buf);
        return false;
    }

    argv[argc] = NULL;

    out.buf = buf;
    out.argv = argv;
    out.argc = argc;
    return true;
}

static int execve_cmdline(const char *cmdline, char *const envp[] = NULL) {
    cmdline_argv data;
    if (!build_cmdline_argv(cmdline, data)) {
        return -1;
    }

    char *const *use_envp = envp ? envp : environ;
    execve(data.argv[0], data.argv, use_envp);

    free_cmdline_argv(data);
    return -1;
}

static int fork_execve_cmdline(const char *cmdline, char *const envp[] = NULL) {
    pid_t child = fork();
    if (child < 0) {
        return -1;
    }

    if (child == 0) {
        execve_cmdline(cmdline, envp);
        _exit(127);
    }

    int status = 0;
    if (waitpid(child, &status, 0) < 0) {
        return -1;
    }

    return status;
}

#endif // EXEC_CMDLINE_UTILS_H