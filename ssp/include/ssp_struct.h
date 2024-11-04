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
 *      [ header ] 10 bytes
 *          u32 magic
 *          u8  flags
 *          u8-16 payload_size
 *          u8  segments
 *
 *      [ payload: {  6-UINT32_MAX bytes
 *          session_id (optional SSP_SESSION_BIT)
 *          sequence count (optional SSP_SEQUENCE_COUNT_BIT)
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
 *      [ footer (optional) ] 4 bytes
 *          u32 checksum
 *  ]
 */

#define SSP_MAGIC 0xCAFEBABE
#define _SSP_PACKED __attribute__((packed))

#define SSP_FOOTER_BIT				0x80
#define SSP_SESSION_BIT				0x40
#define SSP_SEQUENCE_COUNT_BIT		0x20
#define SSP_ZSTD_COMPRESSION_BIT	0x10
#define SSP_16_BIT_PAYLOAD_BIT		0x08

/**
 * Header structure:
 *
 * [32-bit magic][8-bit flags][8-bit segment count][8-16-bit payload size]
 *
 *  flags bits:
 *     [0 1 2 3 4 5 6 7]
 *      F S Q Z P R R R
 *      
 *      F (0)	- Footer
 *      S (1)	- Session id
 *      Q (2)	- seQuence count 
 *      Z (3)	- Zstd packet compression.
 *      P (4)	- 16-bit Payload size.
 *      R (5-7) - Reserve
 */
typedef struct ssp_header
{
    u32 magic;      // Magic u32
    u8 flags;       // flags
    u8 segments;    // Segment count
    u8 size[];      // Payload Size
} _SSP_PACKED ssp_header_t;

// TODO: Implement dynamic-sized segment header
typedef struct ssp_segment
{
    u16 type;
    u16 size;
    u8  data[];
} _SSP_PACKED ssp_segment_t;

typedef struct ssp_footer
{
    u32 checksum;
} ssp_footer_t;

typedef struct ssp_packet
{
	// The actual packet.
	void*			buf;	
	// The size of packet.
	u32				size;
	u32				header_size;
	u32				payload_size;

	// This will be the same as `void* buf`
    ssp_header_t*	header;	
	// This will point to where the payload starts in `void* buf`
	void*			payload;
	// This will point to where the footer is in `void* buf`
	ssp_footer_t*	footer;
} ssp_packet_t;

#endif // _SSP_STRUCT_H_
