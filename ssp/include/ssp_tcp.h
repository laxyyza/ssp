#ifndef _SSP_TCP_H_
#define _SSP_TCP_H_

#include "ssp.h"

#ifdef __linux__
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>

typedef i32 sock_t;

#endif // __linux__
#ifdef _WIN32
#include <ws2tcpip.h>

typedef SOCKET sock_t;
#endif // _WIN32

enum ssp_sockdomain
{
    SSP_IPv4,
    SSP_IPv6
};

typedef struct 
{
    enum ssp_sockdomain domain; 
    union {
        struct sockaddr_in in;
        struct sockaddr_in6 in6;
    } sockaddr;
    socklen_t addr_len;
    u16 port;
} ssp_addr_t;

typedef struct ssp_tcp_sock
{
    sock_t sockfd;
    ssp_addr_t addr;
    char ipstr[INET6_ADDRSTRLEN];
	i32  send_flags;
    bool connected;
} ssp_tcp_sock_t;

i32 ssp_tcp_sock_create(ssp_tcp_sock_t* sock, enum ssp_sockdomain domain);
i32 ssp_tcp_connect(ssp_tcp_sock_t* sock, const char* ipaddr, u16 port);
i32 ssp_tcp_server(ssp_tcp_sock_t* sock, enum ssp_sockdomain domain, u16 port);
void ssp_tcp_sock_close(ssp_tcp_sock_t* sock);
i32 ssp_tcp_send_io(ssp_tcp_sock_t* sock, ssp_io_t* io);
i32 ssp_tcp_send(ssp_tcp_sock_t* sock, const ssp_packet_t* packet);

#endif // _SSP_TCP_H_
