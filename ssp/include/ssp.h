#ifndef _SSP_H_
#define _SSP_H_
#include "ssp_struct.h"
#include <ght.h>
#include <array.h>
#include "ssp_window.h"
#include "ssp_ring.h"

#define SSP_DEFAULT_TX_TIMEOUT 250.0
#define MAX_SEGMENT_TYPES 127
#define MAX_SEGMENT_COUNT UINT8_MAX

#define _SSP_UNUSED __attribute__((unused))

#define SSP_MORE 2
#define SSP_BUFFERED 3
#define SSP_CALLBACK_NOT_ASSIGN 1
#define SSP_SUCCESS 0
#define SSP_FAILED -1
#define SSP_INCOMPLETE -2
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

/**
 * Initialize the SSP I/O Context.
 * This function sets up a shared/common resource that will be used 
 * by multiple `ssp_io` instances. It provides the necessary 
 * initialization for the context, including setting a magic identifier 
 * and associating application-specific data.
 */
void ssp_io_ctx_init(ssp_io_ctx_t* ctx, u32 magic, void* user_data);

/**
 * Register a callback function for a custom segment type.
 * This allows the application to define custom segment types and 
 * associate them with a handler. The maximum number of segment types 
 * that can be registered is 127 (due to the 7-bit limit).
 */
void ssp_io_ctx_register_dispatch(ssp_io_ctx_t* ctx, u8 type, ssp_segment_callback_t callback);

/**
 * Initialize an `ssp_io` instance.
 * This function initializes an `ssp_io` structure, associating it with 
 * a given SSP I/O context and setting the default transmission flags 
 * for the instance.
 */
void ssp_io_init(ssp_io_t* io, ssp_io_ctx_t* ctx, u8 flags);


u32 ssp_checksum32(const void* data, u64 size);

/**
 * Serializes a packet from the `io->tx.ref_ring` buffer.
 *
 * If the `ref_ring` is empty, NULL is returned. Otherwise, a serialized packet is 
 * created and returned, ready for transmission over the network. The serialized 
 * buffer is stored in `ssp_packet_t->buf`, and its size is in `ssp_packet_t->size`.
 *
 * Once the packet is no longer needed, the application should call `ssp_packet_free()` 
 * to free the memory associated with it.
 */
ssp_packet_t* ssp_io_serialize(ssp_io_t* io);

/** 
 * Frees a SSP packet. If the packet has the `SSP_IMPORTANT_BIT` flag set, it will not be freed 
 * to ensure it can be acknowledged and retransmitted if necessary.
 * 
 * Important packets should be managed automatically by `ssp_io_find_expired_packet()`, 
 * so manual intervention is not required for these packets.
 *
 * The application should always call `ssp_packet_free()` after sending it.
 */
void ssp_packet_free(ssp_packet_t* packet);

/** 
 * - `ssp_io_push_ref()`
 *	Pushes a data reference (type, size, and void* data) into the 
 *	`io->tx.ref_ring` buffer for later serialization using `ssp_io_serialize()`.
 *
 *	NOTE: The `data` pointer must remain valid from the time it is pushed until it is serialized
 *	using `ssp_io_serialize()`. This function does not copy the data, it only holds a reference to it.
 *
 *	The `io->tx.ref_ring` buffer has a maximum size of `UINT8_MAX` (255) data references (limited by the 
 *	SSP protocol's maximum segment count), if the number of references exceeds this size, older data 
 *	references will be overwritten. It is the responsibility of the application to ensure that important
 *	references are not overwritten if they need to be preserved.
 */
ssp_data_ref_t* ssp_io_push_ref(ssp_io_t* io, u8 type, u16 size, const void* data);

/**	
 * - `ssp_io_push_ref_i`
 *	Exact same as `ssp_io_push_ref()` but marks data reference as "Important".
 *
 *	Identical to `ssp_io_push_ref()` but marks the data reference as "Important",
 *	which causes the next call to `ssp_io_serialize()` to set the `SSP_IMPORTANT_BIT` flag
 *	in the resulting packet.
 */
ssp_data_ref_t* ssp_io_push_ref_i(ssp_io_t* io, u8 type, u16 size, const void* data);

/** 
 * - `ssp_io_push_hook_ref()`
 *	Identical to `ssp_io_push_ref()` but allows for a custom callback function 
 *	(`copy_hook`) to be provided for handling data copying. 
 *	This allows custom copying behavior during serialization.
 */
ssp_data_ref_t* ssp_io_push_hook_ref(ssp_io_t* io, u8 type, u16 size, const void* data, ssp_copy_hook_t copy_hook);

/**
 * - `ssp_io_push_hook_ref_i()`
 *	Combines the behavior of `ssp_io_push_hook_ref()` and `ssp_io_push_ref_i()`.
 */
ssp_data_ref_t* ssp_io_push_hook_ref_i(ssp_io_t* io, u8 type, u16 size, const void* data, ssp_copy_hook_t copy_hook);

/**
 * Calculate the total size of the payload based on the `ssp_io`'s `ref_ring` buffer.
 * This function computes the size of all data references currently in the `ref_ring`,
 * which are queued for serialization and transmission.
 */
u32  ssp_io_ref_ring_size(const ssp_io_t* io);

/**
 * Deinitialize the `ssp_io` instance.
 * This function cleans up any resources used by the `ssp_io` structure, 
 * ensuring that any dynamically allocated memory is freed.
 */
void ssp_io_deinit(ssp_io_t* io);

/**
 * Parses an arbitrary buffer containing received network data,
 * processes it, and invokes the appropriate type-dispatch callbacks.
 *
 * Returns:
 *  0 (SSP_SUCCESS) - Success: All segments have assigned callbacks.
 *  1 (SSP_SEGMAP_NO_ASSIGN) - Success: At least one segment did not have a callback assigned.
 *  2 (SSP_MORE) - More data: The buffer size exceeds the packet size, indicating that there might be additional data
 *    or another packet in the buffer (e.g., in stream-based protocols like TCP).
 *  3 (SSP_BUFFERED) - Buffered: The packet was buffered and may or may not be processed.
 * -1 (SSP_FAILED) - Failure: The data is invalid.
 * -2 (SSP_INCOMPLETE) - Incomplete: The packet is incomplete.
 * -3 (SSP_NOT_USED) - Not used: All segments did not have a callback assigned.
 */
i32 ssp_io_process(ssp_io_process_params_t* params);

/**
 * Processes buffered packets in the sliding window, if they are properly aligned or the timeout has expired.
 */
i32 ssp_io_process_window(ssp_io_t* io, void* source_data);

/**
 * Checks the important pending packets. If the timeout has expired, the packet will be returned 
 * to be retransmitted.
 */
ssp_packet_t* ssp_io_find_expired_packet(ssp_io_t* io, f64 current_time);

/**
 * Sets the round-trip time (RTT) between the application and peer.
 * This will adjust the timeouts accordingly.
 */
void ssp_io_set_rtt(ssp_io_t* io, f32 rtt_ms);

#endif // _SSP_H
