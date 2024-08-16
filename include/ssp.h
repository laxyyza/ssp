#ifndef _SSP_H_
#define _SSP_H_

#include "ssp_struct.h"

typedef struct 
{
    u16 type;
    u32 size;
    const void* data;
} ssp_seglisten_t;

typedef struct 
{
    ssp_seglisten_t* segments;
    u32 size;   // Actual segments size
    u32 min_size; 
    u32 count;  // How much is in use
    u32 inc_size; // How much to increase by
} ssp_segbuff_t;

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

void    ssp_parse_buf(const void* buf, u64 buf_size);

#endif // _SSP_H_
