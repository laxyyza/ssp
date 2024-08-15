#include "ssp.h"
#include "ssp_struct.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

u32 
ssp_pack_size(u16 payload_size)
{
    return sizeof(ssp_packet_t) + payload_size + sizeof(ssp_footer_t);
}

ssp_packet_t*
ssp_new_empty_packet(void)
{
    ssp_packet_t* packet;

    packet = calloc(1, ssp_pack_size(0));
    packet->header.magic = SSP_MAGIC;

    return packet;
}

ssp_packet_t*
ssp_new_packet_from_payload(const void* payload, u16 size, u8 segments)
{
    ssp_packet_t* packet;

    packet = malloc(ssp_pack_size(size));
    packet->header.magic = SSP_MAGIC;
    packet->header.size = size;
    packet->header.segments = segments;
    memcpy(packet->payload, payload, size);

    return packet;
}

ssp_segment_t* 
ssp_new_segment(u8 type, const void* data, u16 size)
{
    ssp_segment_t* seg;

    seg = malloc(sizeof(ssp_segment_t) + size);
    seg->type = type;
    seg->size = size;
    memcpy(seg->data, data, size);

    return seg;
}

void 
ssp_empty_add_payload(ssp_packet_t** src_packet, const void* payload, u16 size, u8 segments)
{
    ssp_packet_t* packet;
    if (src_packet == NULL || *src_packet == NULL)
        return;
    packet = *src_packet;
    if (packet->header.size != 0)
        return;
    *src_packet = realloc(packet, ssp_pack_size(size));
    packet = *src_packet;

    packet->header.size = size;
    packet->header.segments = segments;
    memcpy(packet->payload, payload, size);
}

u32 
ssp_seg_size(const ssp_segment_t* seg)
{
    return sizeof(ssp_segment_t) + seg->size;
}

ssp_footer_t*  
ssp_get_footer(ssp_packet_t* packet)
{
    uint8_t* u8packet = (u8*)packet;
    ssp_footer_t* footer;
    if (packet == NULL || packet->header.size == 0)
        return NULL;
    footer = (ssp_footer_t*)(u8packet + (sizeof(ssp_packet_t) + packet->header.size));
    return footer;
}
