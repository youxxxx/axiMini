/* SIMULATED ransomware behaviour, harmless: only touches files it creates itself in /work
 * (a tmpfs inside the container). Pattern: create documents -> write "<name>.locked" copies
 * (XOR 0x5A, not real crypto) -> delete originals -> drop a ransom note. */
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#define N 20
int main(void) {
    char a[64], b[64];
    mkdir("/work/docs", 0700);
    for (int i = 0; i < N; i++) {
        snprintf(a, sizeof a, "/work/docs/report_%02d.docx", i);
        FILE *f = fopen(a, "w"); if (!f) return 1;
        fprintf(f, "quarterly report %d\n", i); fclose(f);
    }
    for (int i = 0; i < N; i++) {
        snprintf(a, sizeof a, "/work/docs/report_%02d.docx", i);
        snprintf(b, sizeof b, "/work/docs/report_%02d.docx.locked", i);
        FILE *in = fopen(a, "r"), *out = fopen(b, "w");
        if (!in || !out) return 1;
        int c; while ((c = fgetc(in)) != EOF) fputc(c ^ 0x5A, out);
        fclose(in); fclose(out);
        unlink(a);
    }
    FILE *note = fopen("/work/docs/README_RESTORE_FILES.txt", "w");
    if (note) { fputs("SIMULATION: your files were 'encrypted' (XOR) by a harmless test program.\n", note); fclose(note); }
    return 0;
}
