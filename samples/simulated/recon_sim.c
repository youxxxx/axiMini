/* SIMULATED reconnaissance / credential access: read the user list, try the password hashes,
 * enumerate running processes through /proc. Read-only; /etc/shadow is expected to be denied. */
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/utsname.h>
#include <unistd.h>
int main(void) {
    char buf[256]; struct utsname u; uname(&u);
    const char *files[] = {"/etc/passwd", "/etc/shadow", "/etc/hostname"};
    for (int i = 0; i < 3; i++) {
        int fd = open(files[i], O_RDONLY);
        if (fd >= 0) { read(fd, buf, sizeof buf); close(fd); }
    }
    DIR *d = opendir("/proc"); struct dirent *e;
    while (d && (e = readdir(d))) {
        if (!isdigit((unsigned char)e->d_name[0])) continue;
        snprintf(buf, sizeof buf, "/proc/%s/cmdline", e->d_name);
        int fd = open(buf, O_RDONLY);
        if (fd >= 0) { read(fd, buf, sizeof buf); close(fd); }
    }
    if (d) closedir(d);
    return 0;
}
