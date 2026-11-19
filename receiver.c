/*
 * receiver.c - PC2: accepts one TCP connection and saves the data to a file.
 * Usage: receiver <Port> <OutputFile>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define CHUNK_SIZE 8192

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
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <Port> <OutputFile>\n", argv[0]);
        return EXIT_FAILURE;
    }
    int port = atoi(argv[1]);
    const char *out_path = argv[2];

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); return EXIT_FAILURE; }
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) { perror("bind"); return EXIT_FAILURE; }
    if (listen(server_fd, 1) < 0) { perror("listen"); return EXIT_FAILURE; }

    printf("[Receiver] Listening on port %d\n", port);
    fflush(stdout);

    int client = accept(server_fd, NULL, NULL);
    if (client < 0) { perror("accept"); return EXIT_FAILURE; }

    int fd = open(out_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) { perror("open output file"); return EXIT_FAILURE; }

    char buf[CHUNK_SIZE];
    ssize_t n;
    long total = 0;
    while ((n = read(client, buf, sizeof(buf))) > 0) {
        if (write_all(fd, buf, n) < 0) { perror("write"); return EXIT_FAILURE; }
        total += n;
    }

    printf("[Receiver] Received %ld bytes. Saved to %s\n", total, out_path);
    close(fd);
    close(client);
    close(server_fd);
    return 0;
}
