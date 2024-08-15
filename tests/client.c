#include "ssp_tcp.h"

int main(void)
{
    const char* ipaddr = "127.0.0.1";
    const char* msg = "SSP - Simple Segmented Protocol";
    u16 port = 8080;
    ssp_tcp_sock_t sock;

    ssp_tcp_sock_create(&sock, SSP_IPv4);
    if (ssp_tcp_connect(&sock, ipaddr, port) == -1)
        return -1;

    ssp_tcp_send_msg(&sock, msg);
    ssp_tcp_sock_close(&sock);

    return 0;
}
