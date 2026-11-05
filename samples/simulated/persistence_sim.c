/* SIMULATED persistence: try to install itself in autostart locations. The sandbox rootfs is
 * read-only and the user is 'nobody', so every attempt is expected to fail (EROFS / EACCES). */
#include <fcntl.h>
#include <unistd.h>
int main(void) {
    const char *targets[] = {"/etc/cron.d/system-update", "/etc/profile.d/update.sh",
                             "/etc/init.d/update", "/root/.bashrc"};
    for (int i = 0; i < 4; i++) {
        int fd = open(targets[i], O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) { write(fd, "# simulation\n", 13); close(fd); }
    }
    return 0;
}
