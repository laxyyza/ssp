#ifndef _SSP_H_
#define _SSP_H_

#include "ssp_struct.h"

ssp_packet_t*  ssp_empty_packet(void);
ssp_segment_t* ssp_new_segment(u8 type, const void* data, u16 size);
ssp_packet_t*  ssp_new_packet_from_payload(const void* payload, u16 size, u8 segments);
void           ssp_empty_add_payload(ssp_packet_t** packet, const void* payload, u16 size, u8 segments);
ssp_footer_t*  ssp_get_footer(ssp_packet_t* packet);

u32     ssp_pack_size(u32 payload_size, u8 footer);
u32     ssp_seg_size(const ssp_segment_t* seg);

u32     ssp_checksum32(const void* data, u64 size);

#endif // _SSP_H_
