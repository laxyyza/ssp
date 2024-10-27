#include "ssp.h"
#include "ght.h"
#include "ssp_struct.h"
#include "sspint.h"
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

u64 
ssp_calc_psize(u32 payload_size, u8 flags)
{
    return sizeof(ssp_packet_t) + 
            payload_size + 
            (sizeof(ssp_footer_t) * ((flags & SSP_FOOTER_BIT) >> 7));
}

u64 
ssp_packet_size(const ssp_packet_t* packet)
{
    return ssp_calc_psize(packet->header.size,
                          packet->header.flags);
}

u64 
ssp_checksum_size(const ssp_packet_t* packet)
{
    return ssp_calc_psize(packet->header.size, 0);
}

u64 
ssp_seg_size(const ssp_segment_t* seg)
{
    return sizeof(ssp_segment_t) + seg->size;
}

ssp_packet_t*
ssp_new_packet(u32 size, u8 flags)
{
    ssp_packet_t* packet;

    packet = calloc(1, ssp_calc_psize(size, flags));
    packet->header.magic = SSP_MAGIC;
    packet->header.flags = flags;
    packet->header.size = size;

    return packet;
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

    ssp_serialize(packet, segbuf);

    if ((footer = ssp_get_footer(packet)))
        footer->checksum = ssp_checksum32(packet, ssp_calc_psize(payload_size, 0));

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
    if (segbuf == NULL)
        return;

    segbuf->count = 0;
    ssp_segbuff_resize(segbuf, segbuf->min_size);
}

static i32
ssp_parse_payload(ssp_state_t* state, const ssp_packet_t* packet)
{
    i32 ret = SSP_SUCCESS;
    u32 offset = 0;
    ssp_segment_t* segment;
    ssp_segmap_callback_t segmap_callback;
    bool segmap_called = false;

    for (u32 i = 0; i < packet->header.segments; i++)
    {
        segment = (ssp_segment_t*)(packet->payload + offset);

        if ((segmap_callback = ssp_get_segmap(state, segment->type)))
        {
            segmap_callback(segment, state->user_data);
            segmap_called = true;
        }
        else
            ret = SSP_SEGMAP_NO_ASSIGN;

        offset += segment->size + sizeof(ssp_segment_t);
    }
    return (segmap_called) ? ret : SSP_NOT_USED;
}

i32
ssp_parse_buf(ssp_state_t* state, const void* buf, u64 buf_size)
{
    i32 ret;
    const ssp_packet_t* packet = buf;
    ssp_footer_t* footer = NULL;
    u32 our_checksum;
    u64 packet_size;
    bool another_packet = false;

    if (packet->header.magic != SSP_MAGIC)
        return SSP_FAILED;

    packet_size = ssp_packet_size(packet);
    if (packet_size > buf_size)
        return SSP_INCOMPLETE;
    else if (packet_size < buf_size)
        another_packet = true;

    if ((footer = ssp_get_footer(packet)))
    {
        our_checksum = ssp_checksum32(packet, ssp_checksum_size(packet));
        if (our_checksum != footer->checksum)
            return -1;
    }

    ret = ssp_parse_payload(state, packet);

    return (another_packet) ? SSP_MORE : ret;
}
