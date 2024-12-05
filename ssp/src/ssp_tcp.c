#include "ssp_tcp.h"
#include <stdio.h>

i32 
ssp_tcp_sock_create(ssp_tcp_sock_t* sock, enum ssp_sockdomain ssp_domain)
{
    i32 ret = 0;
    i32 domain = (ssp_domain == SSP_IPv6) ? AF_INET6 : AF_INET;

    if ((ret = sock->sockfd = socket(domain, SOCK_STREAM, 0)) == -1)
    {
        perror("socket");
        goto out;
    }

    sock->addr.domain = ssp_domain;

out:
    return ret;
}

i32 
ssp_tcp_connect(ssp_tcp_sock_t* sock, const char* ipaddr, u16 port)
{
    i32 ret = 0;
    struct sockaddr* addr = (struct sockaddr*)&sock->addr.sockaddr;

    switch (sock->addr.domain)
    {
        case SSP_IPv6:
            // TODO
            break;
        case SSP_IPv4:
        default:
            sock->addr.sockaddr.in.sin_family = AF_INET;
            sock->addr.sockaddr.in.sin_port = htons(port);
            sock->addr.sockaddr.in.sin_addr.s_addr = inet_addr(ipaddr);
            sock->addr.addr_len = sizeof(struct sockaddr_in);
            break;
    }

    printf("SSP TCP Connecting to %s:%u... ",
           ipaddr, port);
    fflush(stdout);

    if ((ret = connect(sock->sockfd, addr, sock->addr.addr_len)) == -1)
    {
        perror("FAILED");
        sock->connected = false;
    }
    else
    {
        printf("Connected!\n");
        sock->connected = true;
    }

    return ret;
}

i32 
ssp_tcp_server(ssp_tcp_sock_t* sock, enum ssp_sockdomain domain, u16 port)
{
    if (ssp_tcp_sock_create(sock, domain) == -1)
        return -1;

    switch (sock->addr.domain)
    {
        case SSP_IPv6:
            // TODO
            break;
        case SSP_IPv4:
        default:
            sock->addr.sockaddr.in.sin_family = AF_INET;
            sock->addr.sockaddr.in.sin_port = htons(port);
            sock->addr.sockaddr.in.sin_addr.s_addr = INADDR_ANY;
            sock->addr.addr_len = sizeof(struct sockaddr_in);
            break;
    }

    int opt = 1;

    if (setsockopt(sock->sockfd, SOL_SOCKET, SO_REUSEADDR, (void*)&opt, sizeof(int)) == -1)
    {
        perror("setsockopt");
        goto err;
    }

    if (bind(sock->sockfd, (struct sockaddr*)&sock->addr.sockaddr.in, sock->addr.addr_len) == -1)
    {
        perror("bind");
        goto err;
    }

    if (listen(sock->sockfd, 100) == -1)
    {
        perror("listen");
        goto err;
    }

    return 0;
err:
    ssp_tcp_sock_close(sock);
    return -1;
}

void 
ssp_tcp_sock_close(ssp_tcp_sock_t* sock)
{
#ifdef __linux__
    close(sock->sockfd);
#endif
#ifdef _WIN32
	closesocket(sock->sockfd);
#endif
	sock->connected = false;
}

i32 
ssp_tcp_send_io(ssp_tcp_sock_t* sock, ssp_io_t* io)
{
	if (io == NULL)
		return -1;

	i32 ret;
	ssp_packet_t* packet;

	packet = ssp_io_serialize(io);
	if (packet == NULL)
		return -1;

	ret = ssp_tcp_send(sock, packet);
	ssp_packet_free(packet);

	return ret;
}

i32 
ssp_tcp_send(ssp_tcp_sock_t* sock, const ssp_packet_t* packet)
{
    i32 ret;
    if (packet == NULL)
        return -1;

    if ((ret = send(sock->sockfd, packet->buf, packet->size, sock->send_flags)) == -1)
        perror("send");

    return ret;
}
