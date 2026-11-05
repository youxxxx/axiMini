/* SIMULATED process storm (bounded, not a real fork bomb): try to start 100 short-lived
 * children. The container's --pids-limit caps how many can exist; the rest fail with EAGAIN. */
#include <sys/wait.h>
#include <unistd.h>
int main(void) {
    for (int i = 0; i < 100; i++) {
        pid_t p = fork();
        if (p == 0) { sleep(2); _exit(0); }
    }
    while (wait(NULL) > 0) {}
    return 0;
}
