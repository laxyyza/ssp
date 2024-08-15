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
 *      [ header ] 
 *          magic
 *          payload_size
 *          u8 segments
 *
 *      [ payload: {
 *          segment0, 
 *              type
 *              size
 *              data
 *          segment1, 
 *              type
 *              size
 *              data
 *          ...
 *      }] 
 *
 *      [ footer ] 
 *          checksum
 *  ]
 */

#define SSP_MAGIC 0xDEAD00BEEF00ABCD

typedef struct ssp_header
{
    u64 magic;      // Magic u64
    u16 size;       // Payload Size
    u16 segments;   // Segment count
} ssp_header_t;

typedef struct ssp_segment
{
    u16 type;
    u16 size;
    u8  data[];
} ssp_segment_t;

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
