#include "ssp.h"
#include "ssp_struct.h"
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PORT 8080

typedef struct 
{
    i32 sockfd;
    struct sockaddr_in addr;
    socklen_t addr_len;
    ssp_segbuff_t segbuf;
} udp_client_t;

udp_client_t client = {0};
const char* ipaddr = "0.0.0.0";

i32
client_init(void)
{
    if ((client.sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
        perror("socket");
        return -1;
    }

    client.addr.sin_family = AF_INET;
    client.addr.sin_addr.s_addr = inet_addr(ipaddr);
    client.addr.sin_port = htons(PORT);
    client.addr_len = sizeof(struct sockaddr_in);

    ssp_segbuff_init(&client.segbuf, 10);

    return 0;
}

static void 
print_sending_packet(const ssp_packet_t* packet, u64 size)
{
    ssp_footer_t* footer;
    u32 offset = 0;
    ssp_segment_t* segment;

    printf("\n> UDP Client sending packet (%lu bytes) to: %s:%u\n", size, ipaddr, PORT);
    printf("> Header:\n");
    printf("\tMagic: %X\n", packet->header.magic);
    printf("\tFlags: %X\n", packet->header.flags);
    printf("\tSize: %u\n", packet->header.size);
    printf("\tSegments: %u\n", packet->header.segments);

    printf("> Payload:\n");
    for (u32 i = 0; i < packet->header.segments; i++)
    {
        segment = (ssp_segment_t*)(packet->payload + offset);
        char* data = strndup((const char*)segment->data, segment->size);

        printf("\tsegment%u: [type: %X, size: %u]: '%s'\n", 
               i, segment->type, segment->size, data);

        offset += segment->size + sizeof(ssp_segment_t);
        free(data);
    }

    if ((footer = ssp_get_footer(packet)))
    {
        printf("> Footer:\n");
        printf("\tChecksum: %X\n", footer->checksum);
    }
}

static i64
client_send(const ssp_packet_t* packet)
{
    if (packet == NULL)
        return -1;

    i64 ret;
    u64 size = ssp_pack_size(packet->header.size, packet->header.flags);

    print_sending_packet(packet, size);

    if ((ret = sendto(client.sockfd, packet, size, 0, (struct sockaddr*)&client.addr, client.addr_len)) == -1)
        perror("sendto");

    return ret;
}

i32 
main(void)
{
    const char* msg1 = "Sending this message on top of UDP!";
    const char* msg2 = "Using SSP on UDP!123456789";
    u32 len1 = strlen(msg1);
    u32 len2 = strlen(msg2);
    ssp_packet_t* packet;

    client_init();

    ssp_segbuff_add(&client.segbuf, 0x0, len1, msg1);
    ssp_segbuff_add(&client.segbuf, 0xFFFF, len2, msg2);
    ssp_segbuff_add(&client.segbuf, 0xDDDD, len1, msg1);

    packet = ssp_serialize_packet(&client.segbuf);
    client_send(packet);
    free(packet);

    ssp_segbuff_add(&client.segbuf, 0x2222, len1, msg1);

    packet = ssp_serialize_packet(&client.segbuf);
    client_send(packet);
    free(packet);

    packet = ssp_serialize_packet(&client.segbuf);
    client_send(packet);
    free(packet);

    return 0;
}
