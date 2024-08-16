#include <asm-generic/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <ssp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <poll.h>

#define PORT 8080

typedef struct 
{
    i32 sockfd;
    struct sockaddr_in addr;
    socklen_t addr_len;
} udp_server_t;

udp_server_t server;

static i32 
udp_server_init(void)
{
    if ((server.sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
        perror("socket");
        return -1;
    }

    server.addr.sin_family = AF_INET;
    server.addr.sin_addr.s_addr = INADDR_ANY;
    server.addr.sin_port = htons(PORT);
    server.addr_len = sizeof(struct sockaddr_in);

    i32 opt = 1;
    if (setsockopt(server.sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(i32)) == -1)
    {
        perror("setsockopt");
        return -1;
    }

    if (bind(server.sockfd, (struct sockaddr*)&server.addr, server.addr_len) == -1)
    {
        perror("bind");
        return -1;
    }

    return 0;
}

static void
read_socket(void)
{
    void* buf;
    u64 buf_size = 4096;
    i64 bytes_read;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(struct sockaddr_in);
    char ipaddr[INET_ADDRSTRLEN];

    buf = malloc(buf_size);

    if ((bytes_read = recvfrom(server.sockfd, buf, buf_size, 0, (struct sockaddr*)&addr, &addr_len)) == -1)
    {
        perror("recvfrom");
        exit(-1);
    }

    inet_ntop(AF_INET, &addr.sin_addr, ipaddr, INET_ADDRSTRLEN);

    printf("\nRecv %lu bytes from %s...\n", bytes_read, ipaddr);

    ssp_parse_buf(buf, bytes_read);
    free(buf);
}

static void
udp_server_run(void)
{
    i32 ret;
    struct pollfd pfd = {
        .fd = server.sockfd,
        .events = POLLIN
    };

    printf("Bound to port %u\n", PORT);

    for (;;)
    {
        if ((ret = poll(&pfd, 1, -1)) == -1)
        {
            perror("poll");
            return;
        }

        read_socket();
    }
}

i32
main(void)
{
    if (udp_server_init() == -1)
        return -1;
    udp_server_run();

    return 0;
}
