#ifndef _SSP_H_
#define _SSP_H_

#include "ssp_struct.h"
#include <ght.h>

#define _SSP_UNUSED __attribute__((unused))
#define SSP_SUCCESS 0
#define SSP_FAILED -1
#define SSP_SEGMAP_NO_ASSIGN 1
#define SSP_INCOMPLETE -2
#define SSP_MORE 2
#define SSP_NOT_USED -3

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
	u32 session_id;
	u8  flags;		// Packet Flags
} ssp_segbuff_t;

typedef void (*ssp_segmap_callback_t)(const ssp_segment_t*, void* user_data, void* source_data);

// Return false if failed
typedef bool (*ssp_session_verify_callback_t)(u32 session_id, void* user_data, void* source_data, void** new_source);

typedef struct 
{
    ssp_segbuff_t segbuf;   // Segment Buffer
    ght_t segment_map;      // Segment Map (Segment Type Function-pointer map)
	ssp_session_verify_callback_t verify_session;
    void* user_data;
} ssp_state_t;

void ssp_state_init(ssp_state_t* state);
void ssp_segmap(ssp_state_t* state, u16 segtype, ssp_segmap_callback_t callback);

/**
 *  Allocate new ssp_packet_t with it's payload size.
 */
ssp_packet_t* ssp_new_packet(u32 size, u8 flags);

/**
 *  Returns the pointer to the packet's footer.
 *  Returns NULL if packet has no footer.
 */
ssp_footer_t* ssp_get_footer(const ssp_packet_t* packet);

/**
 *  Calculate Packet Size based on payload size and flags.
 */
u64 ssp_calc_psize(u32 payload_size, u8 footer);

/**
 *  Get packet size. Header + Payload + footer (if it has footer)
 */
u64 ssp_packet_size(const ssp_packet_t* packet);

/** 
 *  Segment size. Segment header + Segment's Data
 */
u64 ssp_seg_size(const ssp_segment_t* seg);

/**
 * Serializes a packet from the `segbuf`.
 * Returns a pointer to an `ssp_packet_t` structure allocated on the heap,
 * ready for transmission over the network.
 * The returned packet should be freed using the standard `free()` function.
 *
 * If `segbuf->count` is zero, returns NULL.
 */
ssp_packet_t* ssp_serialize_packet(ssp_segbuff_t* segbuf);

/**
 *  Initialize segbuff array with its initial size.
 */
void ssp_segbuff_init(ssp_segbuff_t* segbuf, u32 init_size, u8 flags);

/**
 *  Append pointer to data, and it's type and size.
 */
void ssp_segbuff_add(ssp_segbuff_t* segbuf, u16 type, u32 size, const void* data);

/**
 * Clears the segbuff array.
 *
 * This operation resets `segbuf->count` to zero and may resize the buffer.
 */
void ssp_segbuff_clear(ssp_segbuff_t* segbuf);

/**
 * Parses an arbitrary buffer containing received network data,
 * and invokes the appropriate segment-map callbacks.
 *
 * Returns 0 (SSP_SUCCESS) on success when all segments have assigned callbacks.
 * Returns 1 (SSP_SEGMAP_NO_ASSIGN) if successful but at least one segment did 
 *  not have a callback assigned.
 * Returns -1 (SSP_FAILED) if the data is invalid.
 * Returns -2 (SSP_INCOMPLETE) if packet is incomplete.
 * Returns -3 (SSP_NOT_USED) if all segments did not have a callback assigned.
 * Returns 2 (SSP_MORE) if the buffer size is larger than the packet size, indicating
 * that there might be additional data or another packet in the buffer 
 * (e.g., in stream-based protocols like TCP).
 *
 * `source_data` - Pointer to metadata containing information about the origin of the network buffer.
 */
i32 ssp_parse_buf(ssp_state_t* state, const void* buf, u64 buf_size, void* source_data);

#endif // _SSP_H_
