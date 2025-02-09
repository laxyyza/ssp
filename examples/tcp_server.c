#include "ssp.h"
#include "ssp_struct.h"
#include "ssp_tcp.h"
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include "ght.h"
#include "sspint.h"

#define PORT 8080
#define MAX_EVENTS 16

typedef struct client
{
    ssp_tcp_sock_t sock;
} client_t;

typedef struct
{
    i32 epfd;
    ssp_tcp_sock_t tcp_sock;
    ght_t clients;
    struct epoll_event events[MAX_EVENTS];
    bool running;
    ssp_state_t ssp_recv_state;
} server_t;

server_t server = {0};


static i32
server_add_fd(i32 fd)
{
    i32 ret;
    struct epoll_event ev = {
        .data.fd = fd,
        .events = EPOLLIN 
    };
    if ((ret = epoll_ctl(server.epfd, EPOLL_CTL_ADD, fd, &ev)) == -1)
        perror("epoll_ctl");
    return ret;
}

static void
segmap_zero(const ssp_segment_t* segment, _SSP_UNUSED void* data)
{
    char* str = strndup((const char*)segment->data, segment->size);
    printf("\n\n>> segmap_zero: '%s'\n\n\n", str);
    free(str);
}

static i32
server_init(void)
{
    i32 ret = 0;
    ght_init(&server.clients, 10, free);

    if (ssp_tcp_server(&server.tcp_sock, SSP_IPv4, PORT) == -1)
        return -1;

    if ((server.epfd = epoll_create1(EPOLL_CLOEXEC)) == -1)
    {
        perror("epoll_create1");
        return -1;
    }
    if (server_add_fd(server.tcp_sock.sockfd) == -1)
        return -1;

    ssp_state_init(&server.ssp_recv_state);
    ssp_segmap(&server.ssp_recv_state, 0, segmap_zero);
    ssp_segmap(&server.ssp_recv_state, 1, segmap_zero);

    server.running = true;

    return ret;
}

static void
server_new_client(void)
{
    client_t* client;
    i32 fd;

    client = calloc(1, sizeof(client_t));
    client->sock.addr.addr_len = server.tcp_sock.addr.addr_len;
    fd = accept(server.tcp_sock.sockfd, (struct sockaddr*)&client->sock.addr.sockaddr.in, &client->sock.addr.addr_len);
    if (fd == -1)
    {
        perror("accept");
        free(client);
        return;
    }
    client->sock.sockfd = fd;
    inet_ntop(AF_INET, &client->sock.addr.sockaddr.in.sin_addr, client->sock.ipstr, INET_ADDRSTRLEN);

    ght_insert(&server.clients, client->sock.sockfd, client);
    server_add_fd(client->sock.sockfd);
    client->sock.connected = true;

    printf("Client: %s connected! fd: %d\n", client->sock.ipstr, fd);
}

static void 
remove_client(client_t* client)
{
    printf("Client %s disconnected.\n", client->sock.ipstr);
    epoll_ctl(server.epfd, EPOLL_CTL_DEL, client->sock.sockfd, NULL);
    ssp_tcp_sock_close(&client->sock);
    ght_del(&server.clients, client->sock.sockfd);
}

static void 
read_client(client_t* client)
{
    printf("\n\n");
    void* buf;
    u64   buf_size = 4096;
    i64   bytes_read = 0;

    buf = malloc(buf_size);

    if ((bytes_read = recv(client->sock.sockfd, buf, buf_size, 0)) == -1)
    {
        perror("recv");
        remove_client(client);
        return;
    }
    else if (bytes_read == 0)
    {
        remove_client(client);
        return;
    }

    ssp_parse_buf(&server.ssp_recv_state, buf, bytes_read);
    free(buf);
}

static void
server_run(void)
{
    i32 nfds;
    while (server.running)
    {
        if ((nfds = epoll_wait(server.epfd, server.events, MAX_EVENTS, -1)) == -1)
        {
            perror("epoll_wait");
            break;
        }

        for (i32 i = 0; i < nfds; i++)
        {
            const struct epoll_event* ev = server.events + i;
            i32 fd = ev->data.fd;
            if (fd == server.tcp_sock.sockfd)
            {
                server_new_client();
            }
            else
            {
                client_t* client = ght_get(&server.clients, fd);
                if (client == NULL)
                {
                    printf("YO? fd: %d no client?\n", fd);
                    return;
                }
                read_client(client);
            }
        }
    }
}

i32
main(void)
{
    if (server_init() == -1)
        return -1;

    server_run();

    return 0;
}
