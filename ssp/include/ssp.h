#ifndef _SSP_H_
#define _SSP_H_
#include "ssp_struct.h"
#include <ght.h>
#include <array.h>
#include "ssp_window.h"
#include "ssp_ring.h"

#define SSP_DEFAULT_TX_TIMEOUT 250.0
#define MAX_SEGMENT_TYPES 128
#define MAX_SEGMENT_COUNT UINT8_MAX

#define _SSP_UNUSED __attribute__((unused))

#define SSP_BUFFERED 3
#define SSP_CALLBACK_NOT_ASSIGN 1
#define SSP_SUCCESS 0
#define SSP_FAILED -1
#define SSP_INCOMPLETE -2
#define SSP_MORE 2
#define SSP_NOT_USED -3

typedef void (*ssp_copy_hook_t)(void* dst, const void* src, u16 size);

typedef struct 
{
    u8			type;
    u16			size;
    const void* data;
	bool		important;

	/* Custom copy callback . */
	ssp_copy_hook_t copy;
} ssp_data_ref_t;

typedef struct 
{
	i32 min;
	i32 max;
} ssp_ack_tracking_t;

typedef struct ssp_io ssp_io_t;
typedef void (*ssp_segment_callback_t)(const ssp_segment_t* segment, void* user_data, void* source_data);

// Return false if failed
typedef bool (*ssp_session_verify_callback_t)(u32 session_id, 
											  void* user_data, 
											  void* source_data, 
											  void** new_source,
											  ssp_io_t** io);

/**
 *	SSP I/O Context 
 **/
typedef struct 
{
	/** 
	 * Dispatch table for segment types, allowing the 
	 * application to register callbacks for each 
	 * segment type. 
	 **/
	ssp_segment_callback_t dispatch_table[MAX_SEGMENT_TYPES];

	/**
	 * Callback for identifying and verifying the session, 
	 * allowing the application to identify the peer and 
	 * verify the session (used with SSP_SESSION_BIT). 
	 **/
	ssp_session_verify_callback_t verify_session;

	/**
	 * Unique identifier for all packets,
	 * used for packet validation.
	 **/
	u32 magic;

	/* Application-specific data. */
    void* user_data;

	f64 current_time;
} ssp_io_ctx_t;

/**
 *	SSP I/O TX 
 **/
typedef struct 
{
	/* Ring buffer of data references for serialization. */
	ssp_ring_t ref_ring;

	/* Transmission sequence count, used only when the SSP_IMPORTANT_BIT flag is set. */
	u16 seqc;

	/* Default transmission flags. */
	u8 flags;

	/* Array holding pending important packets awaiting acknowledgment. */
	array_t pending;

	/**
	 * Packet timeout duration. If the elapsed time exceeds this value, 
	 * the packet will be retransmitted.
	 */
	f32 packet_timeout_ms;

	/* Maximum number of retransmission timeouts per packet. */
	u32 max_rto;

	struct {
		/* Flag indicating whether packet compression should be applied if size exceeds the threshold. */
		bool auto_do;
		/* Size threshold above which compression will be applied. */
		u32 threshold;

		/* Zstd compression level (higher values indicate more compression). */
		i32 level;
	} compression;

	/* Transmission statistics. */
	u32 rto; // Retransmission timeouts.
	u32 total_packets; // Total number of transmitted packets.
} ssp_io_tx_t;

/**
 *	SSP I/O RX 
 **/
typedef struct 
{
	/* Sliding window used to reorder and process packets in order. */
	ssp_window_t window;

	/* ACK tracking structure, used for serializing and determining which ACKs need to be sent. */
	ssp_ack_tracking_t acks;

	/* Required flags for valid packets; invalid packets are dropped. */
	u8 required_flags;

	/* Status of incomplete packet data. */
	struct {
		ssp_packet_t packet; // Pointer to the incomplete packet.
		u32 current_size;     // Current size of the incomplete packet data.
	} incomplete;

	/* Timestamp of the last received packet. */
	f64 last_timestamp;

	/* Reception statistics. */
	u32 dropped_packets; // Number of dropped packets.
	u32 total_packets;   // Total number of received packets.
} ssp_io_rx_t;

/**
 * SSP I/O 
 **/
typedef struct ssp_io
{
	ssp_io_ctx_t* ctx;
	ssp_io_tx_t tx;
	ssp_io_rx_t rx;

	/* Session ID, used by SSP_SESSION_BIT for identifying sessions. */
	u32 session_id;
} ssp_io_t;

typedef struct 
{
	ssp_io_ctx_t* ctx;			// If `io` is NULL, this must be set.
	ssp_io_t*	io;				// For TCP, when the connection context (ssp_io) is available
	void*		buf;			// The received buffer
	u32			size;			// The size of the buffer.
	void*		peer_data;		// For UDP, holds the received peer address when it's unknown.
	f64			timestamp_s;	// Timestamp of the packet.
} ssp_io_process_params_t;

void ssp_io_ctx_init(ssp_io_ctx_t* ctx, u32 magic, void* user_data);
void ssp_io_ctx_register_dispatch(ssp_io_ctx_t* ctx, u8 type, ssp_segment_callback_t callback);

void ssp_io_init(ssp_io_t* io, ssp_io_ctx_t* ctx, u8 flags);

u32 ssp_checksum32(const void* data, u64 size);

/**
 *  Calculate Packet Size based on payload size and flags.
 */
u32 ssp_calc_psize(u32 payload_size, u32* header_size_p, u32* opt_data_offset, u8 flags);

/** 
 *  Segment size. Segment header + Segment's Data
 */
u32 ssp_seg_size(const ssp_segment_t* seg);

/**
 * Serializes a packet from the `io`.
 * Returns a pointer to an `ssp_packet_t` structure allocated on the heap,
 * ready for transmission over the network.
 * The returned packet should be freed using `ssp_packet_free()`
 *
 * If `io->count` is zero, returns NULL.
 */
ssp_packet_t* ssp_io_serialize(ssp_io_t* io);


void ssp_packet_free(ssp_packet_t* packet);

/**
 *  Appends a pointer to data, along with its type and size, to the segment buffer.
 *
 *  NOTE: The data must remain valid (i.e., not freed, or go out of scope) 
 *        from the time it is added to the buffer until the call to `ssp_serialize_packet()`.
 */
ssp_data_ref_t* ssp_io_push_ref(ssp_io_t* io, u8 type, u16 size, const void* data);

/**
 *	'i' for "Important"
 */
ssp_data_ref_t* ssp_io_push_ref_i(ssp_io_t* io, u8 type, u16 size, const void* data);
ssp_data_ref_t* ssp_io_hook_push_ref(ssp_io_t* io, u8 type, u16 size, const void* data, ssp_copy_hook_t copy_hook);
ssp_data_ref_t* ssp_io_hook_push_ref_i(ssp_io_t* io, u8 type, u16 size, const void* data, ssp_copy_hook_t copy_hook);

/**
 *	Calculate the total size of io if serialized.
 */
u32  ssp_io_serialized_size(const ssp_io_t* io, u8* flags);

void ssp_io_tx_reset(ssp_io_t* io);

void ssp_io_deinit(ssp_io_t* io);

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
i32 ssp_io_process(ssp_io_process_params_t* params);
i32 ssp_parse_sliding_window(ssp_io_ctx_t* ctx, ssp_io_t* io, void* source_data);

ssp_packet_t* ssp_io_find_expired_packet(ssp_io_t* io, f64 current_time);
void ssp_io_set_rtt(ssp_io_t* io, f32 rtt_ms);

#endif // _SSP_H_
