#include "ssp.h"
#include "ght.h"
#include "ssp_struct.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

void 
ssp_state_init(ssp_state_t* state)
{
    ssp_segbuff_init(&state->segbuf, 10);
    ght_init(&state->segment_map, 10, NULL);
}

void 
ssp_segmap(ssp_state_t* state, u16 segtype, ssp_segmap_callback_t callback)
{
    ght_insert(&state->segment_map, segtype, callback);
}

ssp_segmap_callback_t 
ssp_get_segmap(ssp_state_t* state, u16 segtype)
{
    return ght_get(&state->segment_map, segtype);
}

u32 
ssp_pack_size(u32 payload_size, u8 flags)
{
    return sizeof(ssp_packet_t) + 
            payload_size + 
            (sizeof(ssp_footer_t) * ((flags & SSP_FOOTER_BIT) >> 7));
}

ssp_packet_t*
ssp_new_empty_packet(void)
{
    ssp_packet_t* packet;

    packet = calloc(1, ssp_pack_size(0, 0));
    packet->header.magic = SSP_MAGIC;

    return packet;
}

ssp_packet_t*
ssp_new_packet_from_payload(const void* payload, u16 size, u8 segments)
{
    ssp_packet_t* packet;
    u8 flags = SSP_FOOTER_BIT;

    packet = malloc(ssp_pack_size(size, flags));
    packet->header.magic = SSP_MAGIC;
    packet->header.size = size;
    packet->header.segments = segments;
    packet->header.flags = flags;
    memcpy(packet->payload, payload, size);

    return packet;
}

ssp_packet_t*
ssp_new_packet(u32 size, u8 flags)
{
    ssp_packet_t* packet;

    packet = calloc(1, ssp_pack_size(size, flags));
    packet->header.magic = SSP_MAGIC;
    packet->header.flags = flags;
    packet->header.size = size;

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
    u8 flags = SSP_FOOTER_BIT;
    if (src_packet == NULL || *src_packet == NULL)
        return;
    packet = *src_packet;
    if (packet->header.size != 0)
        return;
    *src_packet = realloc(packet, ssp_pack_size(size, flags));
    packet = *src_packet;

    packet->header.size = size;
    packet->header.segments = segments;
    packet->header.flags = flags;
    memcpy(packet->payload, payload, size);
}

u32 
ssp_seg_size(const ssp_segment_t* seg)
{
    return sizeof(ssp_segment_t) + seg->size;
}

ssp_footer_t*  
ssp_get_footer(const ssp_packet_t* packet)
{
    uint8_t* u8packet = (u8*)packet;
    ssp_footer_t* footer;
    if (packet == NULL || packet->header.size == 0 || (packet->header.flags & SSP_FOOTER_BIT) == 0)
        return NULL;
    footer = (ssp_footer_t*)(u8packet + (sizeof(ssp_packet_t) + packet->header.size));
    return footer;
}

u32 
ssp_checksum32(const void* data, u64 size)
{
    const u8* bytes = data;
    uint32_t checksum = 0;

    for (u64 i = 0; i < size; i++) 
    {
        checksum += bytes[i];
        checksum ^= (checksum << 5) | (checksum >> 27); // Rotate and XOR
    }

    // Final mixing to ensure better distribution
    checksum = (checksum ^ (checksum >> 16)) * 0x45d9f3b;
    checksum = (checksum ^ (checksum >> 16)) * 0x45d9f3b;
    checksum = checksum ^ (checksum >> 16);

    return checksum;
}

static u32 
ssp_get_segbuf_total_size(const ssp_segbuff_t* segbuf)
{
    u32 total = 0;
    for (u32 i = 0; i < segbuf->count; i++)
        total += segbuf->segments[i].size;
    return total;
}

static void
ssp_serialize(ssp_packet_t* packet, ssp_segbuff_t* segbuf)
{
    u32 offset = 0;
    packet->header.segments = segbuf->count;

    for (u32 i = 0; i < segbuf->count; i++)
    {
        const ssp_seglisten_t* seglisten = segbuf->segments + i;
        ssp_segment_t* segment = (ssp_segment_t*)(packet->payload + offset);

        segment->type = seglisten->type;
        segment->size = seglisten->size;
        memcpy(segment->data, seglisten->data, segment->size);

        offset += segment->size + sizeof(ssp_segment_t);
    }
}

ssp_packet_t* 
ssp_serialize_packet(ssp_segbuff_t* segbuf)
{
    ssp_packet_t* packet;
    ssp_footer_t* footer;
    u32 payload_size;
    u8  flags = SSP_FOOTER_BIT;

    if (segbuf->count == 0)
        return NULL;

    payload_size = ssp_get_segbuf_total_size(segbuf) + 
                    (sizeof(ssp_segment_t) * segbuf->count);
    packet = ssp_new_packet(payload_size, flags);

    printf("Serializing... segbuf->count: %u\n", segbuf->count);

    ssp_serialize(packet, segbuf);

    if ((footer = ssp_get_footer(packet)))
        footer->checksum = ssp_checksum32(packet, ssp_pack_size(payload_size, 0));

    ssp_segbuff_clear(segbuf);

    return packet;
}

void 
ssp_segbuff_init(ssp_segbuff_t* segbuf, u32 init_size)
{
    segbuf->segments = calloc(init_size, sizeof(ssp_seglisten_t));
    segbuf->size = init_size;
    segbuf->count = 0;
    segbuf->min_size = init_size;
    segbuf->inc_size = init_size;
}

void 
ssp_segbuff_resize(ssp_segbuff_t* segbuf, u32 new_size)
{
    if (new_size < segbuf->min_size)
        new_size = segbuf->min_size;
    if (new_size == segbuf->size)
        return;

    segbuf->segments = realloc(segbuf->segments, new_size);
    segbuf->size = new_size;
}

void    
ssp_segbuff_add(ssp_segbuff_t* segbuf, u16 type, u32 size, const void* data)
{
    ssp_seglisten_t* seglisten = segbuf->segments + segbuf->count;
    seglisten->type = type;
    seglisten->size = size;
    seglisten->data = data;
    segbuf->count++;

    if (segbuf->count >= segbuf->size)
        ssp_segbuff_resize(segbuf, segbuf->size + segbuf->inc_size);
}

void 
ssp_segbuff_clear(ssp_segbuff_t* segbuf)
{
    segbuf->count = 0;
    ssp_segbuff_resize(segbuf, segbuf->min_size);
}

static void 
ssp_parse_payload(ssp_state_t* state, const ssp_packet_t* packet)
{
    u32 offset = 0;
    ssp_segment_t* segment;
    ssp_segmap_callback_t segmap_callback;

    for (u32 i = 0; i < packet->header.segments; i++)
    {
        segment = (ssp_segment_t*)(packet->payload + offset);

        if ((segmap_callback = ssp_get_segmap(state, segment->type)))
        {
            segmap_callback(segment, state->user_data);
        }
        else
        {
            printf("ssp_parse_payload: No segmap for type: %X.\n", 
                   segment->type);
        }

        // char* data = calloc(segment->size + 1, 1);
        // strncpy(data, (const char*)segment->data, segment->size);
        // printf("> segment%u\n", i);
        // printf("\tType: %X\n", segment->type);
        // printf("\tSize: %u\n", segment->size);
        // printf("\tData: '%s'\n", data);

        offset += segment->size + sizeof(ssp_segment_t);
    }
}

void 
ssp_parse_buf(ssp_state_t* state, const void* buf, u64 buf_size)
{
    const ssp_packet_t* packet = buf;
    ssp_footer_t* footer = NULL;
    u32 our_checksum;
    u64 packet_size;
    bool another_packet = false;
    u64 another_packet_offset = 0;

    if (packet->header.magic != SSP_MAGIC)
    {
        printf("ssp_parse_buf: failed! %X != %X\n",
               packet->header.magic, SSP_MAGIC);
        return;
    }

    packet_size = ssp_pack_size(packet->header.size, packet->header.flags);
    if (packet_size > buf_size)
    {
        printf(">>> Packet incomplete?\n");
    }
    else if (packet_size < buf_size)
    {
        another_packet = true;
        another_packet_offset = packet_size;
    }

    printf("New packet:\n");
    printf("\tFlags: %X\n", packet->header.flags);
    if ((footer = ssp_get_footer(packet)))
        printf("\t\tChecksum: %X\n", footer->checksum);
    printf("\tPayload size: %u\n", packet->header.size);
    printf("\tSegment count: %u\n", packet->header.segments);

    if (footer) 
    {
        our_checksum = ssp_checksum32(packet, 
                                      ssp_pack_size(packet->header.size, 0));
        printf("> Comparing checksum, our: %X == %X ... ",
               our_checksum, footer->checksum);
        if (our_checksum != footer->checksum)
        {
            printf("FAILED!\n");
            return;
        }
        else
            printf("Ok!\n");
    }

    ssp_parse_payload(state, packet);

    if (another_packet)
    {
        printf("\nAnother packet!\n\n");
        ssp_parse_buf(state, buf + another_packet_offset, buf_size - another_packet_offset);
    }
}
