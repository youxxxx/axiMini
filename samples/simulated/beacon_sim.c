/* SIMULATED C2 beacon: try a TCP connection and a UDP "DNS" packet to documentation-only
 * addresses (203.0.113.0/24 = TEST-NET-3, RFC 5737: never routed). With --network none the
 * kernel refuses immediately (ENETUNREACH); nothing ever leaves the container. */
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
int main(void) {
    for (int i = 0; i < 3; i++) {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a; memset(&a, 0, sizeof a);
        a.sin_family = AF_INET; a.sin_port = htons(4444);
        inet_pton(AF_INET, "203.0.113.10", &a.sin_addr);
        connect(s, (struct sockaddr *)&a, sizeof a);
        close(s);
    }
    int u = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in d; memset(&d, 0, sizeof d);
    d.sin_family = AF_INET; d.sin_port = htons(53);
    inet_pton(AF_INET, "203.0.113.53", &d.sin_addr);
    sendto(u, "beacon", 6, 0, (struct sockaddr *)&d, sizeof d);
    close(u);
    return 0;
}
