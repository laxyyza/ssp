#include "ssp_tcp.h"
#include "ssp.h"
#include "ssp_struct.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>

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

void 
ssp_tcp_sock_close(ssp_tcp_sock_t* sock)
{
    close(sock->sockfd);
}

i32 
ssp_tcp_send_msg(ssp_tcp_sock_t* sock, const char* msg)
{
    if (sock->connected == false)
    {
        printf("Cant send message if not connected.\n");
        return -1;
    }

    i32 ret = 0;
    u32 size = strlen(msg);
    ssp_packet_t* packet;
    ssp_segment_t* segmsg;
    ssp_footer_t* footer;

    segmsg = ssp_new_segment(0, msg, size);
    packet = ssp_new_packet_from_payload(segmsg, ssp_seg_size(segmsg), 1);
    footer = ssp_get_footer(packet);
    if (footer)
        footer->checksum = ssp_checksum32(packet, ssp_pack_size(packet->header.size, 0));

    u64 packet_size = ssp_pack_size(packet->header.size, packet->header.footer);

    printf("Sending %lu bytes: [header: %lu, payload: %u, footer: %lu [checksum: %X]]\n",
           packet_size, sizeof(ssp_header_t), packet->header.size, 
           (sizeof(ssp_footer_t) * packet->header.footer),
           footer->checksum);

    if ((ret = send(sock->sockfd, packet, packet_size, 0)) == -1)
        perror("send");

    free(segmsg);
    free(packet);

    return ret;
}
