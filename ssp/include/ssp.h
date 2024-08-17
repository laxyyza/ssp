#ifndef _SSP_H_
#define _SSP_H_

#include "ssp_struct.h"
#include <ght.h>

#define _SSP_UNUSED __attribute__((unused))

typedef struct 
{
    u16 type;
    u32 size;
    const void* data;
} ssp_seglisten_t;

/**
 * segbuf - Segment Buffer
 * 
 * The Segment Buffer is a dynamic array designed to 
 * handle two primary operations: 'add' and 'clear'. 
 * It is used to store data, along with its size and type, 
 * before serializing the `ssp_packet`. This buffer 
 * facilitates the accumulation of segments, which are 
 * later processed by the `ssp_serialize_packet()` function.
 */
typedef struct 
{
    ssp_seglisten_t* segments;
    u32 size;       // Actual segments size
    u32 min_size; 
    u32 count;      // How much is in use
    u32 inc_size;   // How much to increase by
} ssp_segbuff_t;

typedef void (*ssp_segmap_callback_t)(const ssp_segment_t*, void*);

typedef struct 
{
    ssp_segbuff_t segbuf;   // Segment Buffer
    ght_t segment_map;      // Segment Map (Segment Type Function-pointer map)
    void* user_data;
} ssp_state_t;

void ssp_state_init(ssp_state_t* state);
void ssp_segmap(ssp_state_t* state, u16 segtype, ssp_segmap_callback_t callback);

ssp_packet_t*  ssp_empty_packet(void);
ssp_segment_t* ssp_new_segment(u8 type, const void* data, u16 size);
ssp_packet_t*  ssp_new_packet_from_payload(const void* payload, u16 size, u8 segments);
void           ssp_empty_add_payload(ssp_packet_t** packet, const void* payload, u16 size, u8 segments);
ssp_packet_t*  ssp_new_packet(u32 payload_size, u8 footer);
ssp_footer_t*  ssp_get_footer(const ssp_packet_t* packet);

u32     ssp_pack_size(u32 payload_size, u8 footer);
u32     ssp_seg_size(const ssp_segment_t* seg);

u32     ssp_checksum32(const void* data, u64 size);

ssp_packet_t* ssp_serialize_packet(ssp_segbuff_t* segbuf);

void    ssp_segbuff_init(ssp_segbuff_t* segbuf, u32 init_size);
void    ssp_segbuff_add(ssp_segbuff_t* segbuf, u16 type, u32 size, const void* data);
void    ssp_segbuff_clear(ssp_segbuff_t* segbuf);

void    ssp_parse_buf(ssp_state_t* state, const void* buf, u64 buf_size);

#endif // _SSP_H_
