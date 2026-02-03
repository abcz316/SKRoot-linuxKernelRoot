#pragma once
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>

extern char **environ;

static void redirect_stdio_to_devnull(void) {
    int fd = open("/dev/null", O_WRONLY);
    if (fd < 0) return;
    dup2(fd, STDOUT_FILENO); // 1 -> /dev/null
    dup2(fd, STDERR_FILENO); // 2 -> /dev/null
    close(fd);
}

static void start_tricky_store_daemon_loop(const char* moddir) {
    setsid();
    redirect_stdio_to_devnull();
    if (chdir(moddir) != 0) _exit(1);
    for (;;) {
        pid_t pid = fork();
        if (pid < 0) _exit(1);

        if (pid == 0) {
            char *const argv[] = { (char*)"./daemon", NULL };
            execve("./daemon", argv, environ);
            _exit(127);
        }

        int st = 0;
        if (waitpid(pid, &st, 0) < 0) _exit(1);

        int code = 1;
        if (WIFEXITED(st)) code = WEXITSTATUS(st);
        else if (WIFSIGNALED(st)) code = 128 + WTERMSIG(st);
        if (code != 0) _exit(1);
        sleep(2);
    }
}
