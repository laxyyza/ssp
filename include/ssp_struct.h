#ifndef _SSP_STRUCT_H_
#define _SSP_STRUCT_H_

#include "sspint.h"

/**
 * Packet Structure
 *
 *  Header: It includes the first magic identifier, payload size and segment count
 *
 *  Payload: Just an array of segments
 *
 *  Segment: 
 *      type: what type of data is this
 *      size: data size
 *      data[]: the data
 *
 *  Footer: 32-bit checksum of the header + payload
 *
 * Here's an examnple of a packet:
 *  [ [header] [payload: {segment0, segment1, ...}] [footer] ]
 *
 *  [ 
 *      [ header ] 8 + 4 + 2 = 14 bytes
 *          u64 magic
 *          u32 payload_size
 *          1-bit footer
 *          15-bit segments
 *
 *      [ payload: {  6-UINT32_MAX bytes
 *          segment0, 6+ bytes
 *              u16 type
 *              u32 size
 *              u8 data[]
 *          segment1, 
 *              u16 type
 *              u32 size
 *              u8 data[]
 *          ...
 *      }] 
 *
 *      [ footer ] 4 bytes
 *          u32 checksum
 *  ]
 */

#define SSP_MAGIC 0xDEAD00BEEF00ABCD
#define _SSP_PACKED __attribute__((packed))

typedef struct ssp_header
{
    u64 magic;          // Magic u64
    u32 size;           // Payload Size
    u16 footer:1;       // Footer bit
    u16 segments:15;    // Segment count
} _SSP_PACKED ssp_header_t;

typedef struct ssp_segment
{
    u16 type;
    u32 size;
    u8  data[];
} _SSP_PACKED ssp_segment_t;

typedef struct ssp_footer
{
    u32 checksum;
} ssp_footer_t;

typedef struct ssp_packet
{
    ssp_header_t header;
    u8           payload[];
} ssp_packet_t;

#endif // _SSP_STRUCT_H_
