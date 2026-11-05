/* SIMULATED dropper: write a script, make it executable, try to run it.
 * In the sandbox /work is mounted noexec, so the execve is expected to FAIL (EACCES). */
#include <stdio.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
int main(void) {
    FILE *f = fopen("/work/update_helper", "w"); if (!f) return 1;
    fputs("#!/bin/sh\necho second stage (simulation)\n", f); fclose(f);
    chmod("/work/update_helper", 0755);
    pid_t p = fork();
    if (p == 0) { char *argv[] = {"/work/update_helper", NULL}; execv(argv[0], argv); _exit(127); }
    int st; waitpid(p, &st, 0);
    return 0;
}
