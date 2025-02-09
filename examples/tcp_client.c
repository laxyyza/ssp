#include "ssp.h"
#include "ssp_tcp.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

i32 
main(void)
{
    const char* ipaddr = "0.0.0.0";
    const char* msg1 = "SSP - Simple Segmented Protocol";
    const char* msg2 = "Testing Some Stuff";
    u16 port = 8080;
    ssp_tcp_sock_t sock;
    ssp_segbuff_t segbuf;
    u32 len1 = strlen(msg1);
    u32 len2 = strlen(msg2);
    ssp_packet_t* packet;
    printf("sizeof segment: %lu\n", sizeof(ssp_segment_t));

    ssp_tcp_sock_create(&sock, SSP_IPv4);
    if (ssp_tcp_connect(&sock, ipaddr, port) == -1)
        return -1;
    ssp_segbuff_init(&segbuf, 10);

    // Add msg type 6969 & CCCC
    ssp_segbuff_add(&segbuf, 0x6969, len1, msg1);
    ssp_segbuff_add(&segbuf, 0x0, len2, msg2);

    /**
     * Serialize packet from segbuf, send it, and free packet
     * Expect: Send `msg` twice.
     */
    packet = ssp_serialize_packet(&segbuf);
    ssp_tcp_send(&sock, packet);
    free(packet);

    // Add msg as type EEEE
    ssp_segbuff_add(&segbuf, 0xEEEE, len2, msg2);

    /**
     * Serialize packet from segbuf, send it, and free packet
     * Expect: Send `msg` only once.
     */
    packet = ssp_serialize_packet(&segbuf);
    ssp_tcp_send(&sock, packet);
    free(packet);

    /**
     * This time it should not work
     * `ssp_serialize_packet()` should return NULL
     * because ssp_serialize_packet() clears `segbuf`
     */
    packet = ssp_serialize_packet(&segbuf);
    ssp_tcp_send(&sock, packet);
    free(packet);

    ssp_tcp_sock_close(&sock);

    return 0;
}
