#ifndef _SSP_H_
#define _SSP_H_
#include "ssp_struct.h"
#include <ght.h>

#define _SSP_UNUSED __attribute__((unused))
#define SSP_SUCCESS 0
#define SSP_FAILED -1
#define SSP_CALLBACK_NOT_ASSIGN 1
#define SSP_INCOMPLETE -2
#define SSP_MORE 2
#define SSP_NOT_USED -3

typedef struct 
{
    u8 type;
    u16 size;
    const void* data;
} ssp_data_ref_t;

/**
 * segbuf - Segment Buffer
 * 
 * The Segment Buffer is a dynamic array designed to 
 * handle two primary operations: 'add' and 'clear'. 
 * It is used to store reference to data, along with its size and type, 
 * before serializing the `ssp_packet`. This buffer 
 * facilitates the accumulation of segments, which are 
 * later processed by the `ssp_serialize_packet()` function.
 */
typedef struct 
{
    ssp_data_ref_t* data_refs;
    u32 size;       // Actual data_refs size
    u32 min_size; 
    u32 count;      // How much is in use
    u32 inc_size;   // How much to increase by
	u32 session_id;
	u16 seqc_sent;
	u16 last_seqc_recv;
	u8  flags;		// Packet Flags

	struct {
		bool auto_do;
		u32  threshold;
		i32  level;
	} compression;

	struct {
		ssp_packet_t packet;
		u32 current_size;
	} recv_incomplete;
} ssp_segbuf_t;

typedef void (*ssp_segment_callback_t)(const ssp_segment_t*, void* user_data, void* source_data);

// Return false if failed
typedef bool (*ssp_session_verify_callback_t)(u32 session_id, 
											  void* user_data, 
											  void* source_data, 
											  void** new_source,
											  ssp_segbuf_t** segbuf);

typedef struct 
{
    ght_t segment_callbacks;
	ssp_session_verify_callback_t verify_session;
    void* user_data;
	bool debug;
	const char* (*segment_type_str)(u8 type);
} ssp_ctx_t;

void ssp_ctx_init(ssp_ctx_t* ctx);
void ssp_ctx_destroy(ssp_ctx_t* ctx);

/**
 *	Set callback for segment type.
 */
void ssp_segment_callback(ssp_ctx_t* ctx, u16 segtype, ssp_segment_callback_t callback);

/**
 *  Allocate new ssp_packet_t with it's payload size.
 */
ssp_packet_t* ssp_new_packet(u32 size, u8 flags);

/**
 *  Calculate Packet Size based on payload size and flags.
 */
u32 ssp_calc_psize(u32 payload_size, u8 flags);

/** 
 *  Segment size. Segment header + Segment's Data
 */
u32 ssp_seg_size(const ssp_segment_t* seg);

/**
 * Serializes a packet from the `segbuf`.
 * Returns a pointer to an `ssp_packet_t` structure allocated on the heap,
 * ready for transmission over the network.
 * The returned packet should be freed using `ssp_packet_free()`
 *
 * If `segbuf->count` is zero, returns NULL.
 */
ssp_packet_t* ssp_serialize_packet(ssp_segbuf_t* segbuf);


void ssp_packet_free(ssp_packet_t* packet);

/**
 *	Creates packet with only one segment, instead of going 
 *	through `ssp_segbuf_add()` and `ssp_serialize_packet()`.
 */
ssp_packet_t* ssp_insta_packet(ssp_segbuf_t* source_segbuf, u16 type, const void* buf, u64 size);

/**
 *  Initialize segbuf array with its initial size.
 */
void ssp_segbuf_init(ssp_segbuf_t* segbuf, u32 init_size, u8 flags);

/**
 *  Appends a pointer to data, along with its type and size, to the segment buffer.
 *
 *  NOTE: The data must remain valid (i.e., not freed, or go out of scope) 
 *        from the time it is added to the buffer until the call to `ssp_serialize_packet()`.
 */
void ssp_segbuf_add(ssp_segbuf_t* segbuf, u8 type, u16 size, const void* data);

/**
 *	Calculate the total size of segbuf if serialized.
 */
u32  ssp_segbuf_serialized_size(const ssp_segbuf_t* segbuf);

/**
 * Clears the segbuf array.
 *
 * This operation resets `segbuf->count` to zero and may resize the buffer.
 */
void ssp_segbuf_clear(ssp_segbuf_t* segbuf);

void ssp_segbuf_destroy(ssp_segbuf_t* segbuf);

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
i32 ssp_parse_buf(ssp_ctx_t* ctx, ssp_segbuf_t* segbuf, const void* buf, u32 buf_size, void* source_data);

void ssp_print_packet(ssp_ctx_t* ctx, const ssp_packet_t* packet, const u8* payload);

#endif // _SSP_H_
