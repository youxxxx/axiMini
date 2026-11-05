/* Benign: write one settings file in its work dir, read it back. Normal file I/O must NOT be flagged. */
#include <stdio.h>
int main(void) {
    FILE *f = fopen("/work/settings.ini", "w");
    if (!f) return 1;
    fputs("[app]\ntheme=dark\n", f);
    fclose(f);
    char buf[64];
    f = fopen("/work/settings.ini", "r");
    if (f) { fgets(buf, sizeof buf, f); fclose(f); }
    return 0;
}
