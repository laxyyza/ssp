#ifndef _SSP_STRUCT_H_
#define _SSP_STRUCT_H_

#include "sspint.h"

/**
 * Packet Structure
 *
 *  Header: It includes the first magic identifier, flags, segment count and payload size.
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
 *      [ header ] 7-14 bytes
 *          u32   magic
 *          u8    flags
 *          u8	  segment_count
 *          u8-16 payload_size		(SSP_16_BIT_PAYLOAD_BIT for u16)
 *          u32 session_id			(optional SSP_SESSION_BIT)
 *          u16 sequence_count		(optional SSP_SEQUENCE_COUNT_BIT)
 *
 *      [ payload: {  2-UINT16_MAX bytes
 *          segment0, 2+ bytes
 *              u8 type
 *              u8-16 size
 *              u8 data[]
 *          segment1, 
 *              u8 type
 *              u8-16 size
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
#define SSP_IMPORTANT_BIT			0x20
#define SSP_ZSTD_COMPRESSION_BIT	0x10
#define SSP_16_BIT_PAYLOAD_BIT		0x08
#define SSP_ACK_BIT					0x04

/**
 * Header structure:
 *
 * [32-bit magic] [8-bit flags] [8-bit segment count] [8-16-bit payload size]
 *	  [32-bit session id (opt)] [16-bit sequence count | 32-bit ack (opt)]
 *
 *  flags bits:
 *  MSB [7 6 5 4 3 2 1 0] LSB
 *		 F S I Z P A R R
 *      
 *      F (7)	- Footer
 *      S (6)	- Session id
 *      I (5)	- Important
 *      Z (4)	- Zstd packet compression.
 *      P (3)	- 16-bit Payload size.
 *      A (2)	- ACK
 *
 *      R (1-0) - Reserve
 */
typedef struct ssp_header
{
    u32 magic;			// Magic ID
    u8 flags;			// flag bits
    u8 segment_count;
    u8 payload_size[];
	// optional u32 session ID
	// optional u16 sequence count
	// optional u32 ACK
} _SSP_PACKED ssp_header_t;

/**
 *	Segment Header:
 *
 *	[
 *		[ byte 0
 *			[1-bit 16-bit payload size]
 *			[7-bit data type]
 *		] 
 *		[8-16 bit data size] byte 1-2
 *		[data...] byte 2-3+
 *	]
 */
#define SSP_SEGMENT_16BIT_PAYLOAD 0x80

typedef struct ssp_segment
{
    u8  type;
    u16 size;
	u8* data;
} ssp_segment_t;

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

	/*	Meta data in header (after header->size) */
	struct {
		void* buf;
		u32* session_id;
		u16* seq;
		u16* ack_min;
		u16* ack_max;
	} opt_data;

	// This will point to where the payload starts in `void* buf`
	void*			payload;
	// This will point to where the footer is in `void* buf`
	ssp_footer_t*	footer;

	u32 retries;
	bool last_retry;

	f64 timestamp;
} ssp_packet_t;

#endif // _SSP_STRUCT_H_
