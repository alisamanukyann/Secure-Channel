/*
 * sender.c - PC1: sends a file to the receiver over TCP.
 * Usage: sender <IP> <Port> <File>
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>

static int write_all(int fd, const char *p, size_t n)
{
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return -1;
        p += w; n -= w;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <IP> <Port> <File>\n", argv[0]);
        return 1;
    }

    int fd = open(argv[3], O_RDONLY);
    if (fd < 0) { perror("open file"); return 1; }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(atoi(argv[2])) };
    if (inet_pton(AF_INET, argv[1], &addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid IP address\n");
        return 1;
    }
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) { perror("connect"); return 1; }

    char buf[8192];
    ssize_t n;
    long total = 0;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        if (write_all(sock, buf, n) < 0) { perror("send"); return 1; }
        total += n;
    }

    close(fd);
    close(sock);
    printf("[Sender] Transfer completed (%ld bytes sent).\n", total);
    return 0;
}
