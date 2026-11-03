#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>

int main(int argc, char *argv[]) {
    if (argc != 4) return fprintf(stderr, "Usage: %s <IP> <Port> <File>\n", argv[0]), 1;
    int sock = socket(AF_INET, SOCK_STREAM, 0), fd = open(argv[3], O_RDONLY);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(atoi(argv[2])) };
    inet_pton(AF_INET, argv[1], &addr.sin_addr);
    connect(sock, (struct sockaddr *)&addr, sizeof(addr));

    char buf[8192]; ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) write(sock, buf, n);
    close(fd); 
    close(sock);
    printf("[Sender] File transfer completed.\n");
    return 0;
}