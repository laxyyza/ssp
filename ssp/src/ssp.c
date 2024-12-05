#define _GNU_SOURCE
#include "ssp.h"
#include <string.h>
#include <stdio.h>
#include <zstd.h>

#define RESEND_SAFETY_MARGIN_MS 50
#define SEQ_HALF (1 << 15)
#define SEQ_MASK 0xFFFF

enum ssp_parse_status
{
	SSP_PARSE_DO_IMMEDIATELY,
	SSP_PARSE_BUFFERED,
	SSP_PARSE_DROPPED,
	SSP_PARSE_FAILED = -1
};

void
ssp_io_ctx_init(ssp_io_ctx_t* ctx, u32 magic, void* user_data)
{
	memset(ctx->dispatch_table, 0, sizeof(ssp_segment_callback_t) * MAX_SEGMENT_TYPES);
	ctx->user_data = user_data;
	ctx->magic = magic;
}

void 
ssp_io_ctx_register_dispatch(ssp_io_ctx_t* ctx, u8 type, ssp_segment_callback_t callback)
{
	if (type >= MAX_SEGMENT_TYPES)
		return;

	ctx->dispatch_table[type] = callback;
}

static inline ssp_segment_callback_t 
ssp_get_segment_callback(ssp_io_ctx_t* ctx, u8 type)
{
    return ctx->dispatch_table[type];
}

u32 
ssp_calc_psize(u32 payload_size, u32* header_size_p, u32* opt_data_offset_p, u8 flags)
{
	u16 header_size = sizeof(ssp_header_t);
	u32 packet_size = payload_size;
	u32 opt_data_offset = 0;

	if (flags & SSP_16_BIT_PAYLOAD_BIT)
		header_size += sizeof(u16); // +2 bytes
	else
		header_size += sizeof(u8); //  +1 byte
	
	if (flags & SSP_FOOTER_BIT)
		header_size += sizeof(ssp_footer_t); // +4 bytes
	
	opt_data_offset = header_size;
	
	if (flags & SSP_SESSION_BIT)
		header_size += sizeof(u32);	// +4 bytes
	if (flags & SSP_IMPORTANT_BIT)
		header_size += sizeof(u16);	// +2 bytes
	if (flags & SSP_ACK_BIT)
		header_size += sizeof(u16) * 2; // +4 bytes

	if (opt_data_offset_p)
	{
		if (opt_data_offset == header_size)
			*opt_data_offset_p = 0;
		else
			*opt_data_offset_p = opt_data_offset;
	}

	packet_size += header_size;
	if (header_size_p)
		*header_size_p = header_size;

	return packet_size;
}

u32 
ssp_checksum_size(const ssp_packet_t* packet)
{
	return packet->header_size + packet->payload_size;
}

static void
ssp_set_header_payload_size(ssp_packet_t* packet, u32 payload_size)
{
	u8 footer_size = (packet->header->flags & SSP_FOOTER_BIT) ? sizeof(ssp_footer_t) : 0;

	if (packet->header->flags & SSP_16_BIT_PAYLOAD_BIT)
		memcpy(packet->header->payload_size, &payload_size, sizeof(u16));
	else
		packet->header->payload_size[0] = (u8)payload_size;

	packet->size = packet->header_size + payload_size + footer_size;
	packet->payload_size = payload_size;
}

static ssp_packet_t*
ssp_new_packet(ssp_io_ctx_t* ctx, u32 payload_size, u8 flags)
{
    ssp_packet_t* packet;
	u32 packet_size;
	u32 header_size;
	u32 opt_data_offset;
	if (payload_size >= UINT8_MAX)
		flags |= SSP_16_BIT_PAYLOAD_BIT;

	packet_size = ssp_calc_psize(payload_size, &header_size, &opt_data_offset, flags);

	packet = calloc(1, sizeof(ssp_packet_t));
    packet->buf = calloc(1, packet_size);
	packet->header = packet->buf;
    packet->header->magic = ctx->magic;
    packet->header->flags = flags;
	packet->header_size = header_size;
	if (opt_data_offset)
		packet->opt_data.buf = packet->buf + opt_data_offset;
	ssp_set_header_payload_size(packet, payload_size);

	packet->payload = (u8*)packet->buf + packet->header_size;
	if (flags & SSP_FOOTER_BIT)
		packet->footer = (ssp_footer_t*)((u8*)packet->payload + payload_size);
	else
		packet->footer = NULL;

    return packet;
}

u32 
ssp_checksum32(const void* data, u64 size)
{
    const u8* bytes = data;
    uint32_t checksum = 0;

    for (u64 i = 0; i < size; i++) 
    {
        checksum += bytes[i];
        checksum ^= (checksum << 5) | (checksum >> 27); // Rotate and XOR
    }

    // Final mixing to ensure better distribution
    checksum = (checksum ^ (checksum >> 16)) * 0x45d9f3b;
    checksum = (checksum ^ (checksum >> 16)) * 0x45d9f3b;
    checksum = checksum ^ (checksum >> 16);

    return checksum;
}

static u32 
ssp_io_ref_ring_size_f(const ssp_io_t* io, u8* flags)
{
    u32 total = 0;
	u32 count = 0;
	const void* read_head = NULL;
	const ssp_data_ref_t* ref;

	while ((ref = ssp_ring_inter(&io->tx.ref_ring, &read_head, &count)))
	{
		u16 data_size = ref->size;
        total += data_size + 1;			// +1 is for type.
		if (data_size >= UINT8_MAX)
			total += sizeof(u16);
		else
			total += sizeof(u8);

		if (flags && ref->important)
			*flags |= SSP_IMPORTANT_BIT;
	}

	if (total == 0 && flags && *flags & SSP_IMPORTANT_BIT)
		*flags ^= SSP_IMPORTANT_BIT;

    return total;
}

u32 
ssp_io_ref_ring_size(const ssp_io_t* io)
{
	return ssp_io_ref_ring_size_f(io, NULL);
}

static void
ssp_serialize_header(ssp_packet_t* packet, ssp_io_t* io)
{
	u32 offset = 0;

	packet->header->segment_count = io->tx.ref_ring.count;

	if (packet->opt_data.buf == NULL)
		return;

	if (packet->header->flags & SSP_SESSION_BIT)
	{
		packet->opt_data.session_id = packet->opt_data.buf + offset;
		*packet->opt_data.session_id = io->session_id;
		offset += sizeof(u32);
	}

	if (packet->header->flags & SSP_IMPORTANT_BIT)
	{
		packet->opt_data.seq = packet->opt_data.buf + offset;
		*packet->opt_data.seq = ++io->tx.seqc;
		offset += sizeof(u16);
	}

	if (packet->header->flags & SSP_ACK_BIT)
	{
		packet->opt_data.ack_min = packet->opt_data.buf + offset;
		offset += sizeof(u16);

		packet->opt_data.ack_max = packet->opt_data.buf + offset;
		offset += sizeof(u16);

		*packet->opt_data.ack_min = (u16)io->rx.acks.min;
		*packet->opt_data.ack_max = (u16)io->rx.acks.max;

		io->rx.acks.min = io->rx.acks.max = -1;
	}
}

static void 
ssp_serialize_payload(ssp_packet_t* packet, ssp_io_t* io)
{
	u32 offset = 0;
	void* payload;
	const ssp_data_ref_t* ref;
	u32   i = 0;
	const void* read_head = NULL;

	if (packet->payload_size == 0)
		return;

	if (packet->header->flags & SSP_ZSTD_COMPRESSION_BIT || 
		(io->tx.compression.auto_do && packet->payload_size > io->tx.compression.threshold))
	{
		payload = malloc(packet->size);
		packet->header->flags |= SSP_ZSTD_COMPRESSION_BIT;
	}
	else
		payload = packet->payload;

	while ((ref = ssp_ring_inter(&io->tx.ref_ring, &read_head, &i)))
    {
		u32 segment_offset = 0;
        u8* segment = payload + offset;

		// We are assuming type is less than 127.
		segment[segment_offset] = ref->type;
		segment_offset++;

		if (ref->size >= UINT8_MAX)
		{
			// Set data size (16-bit)
			*segment |= SSP_SEGMENT_16BIT_PAYLOAD;
			*(u16*)&segment[segment_offset] = ref->size; 
			segment_offset += sizeof(u16);
		}
		else
		{
			// Set data size
			segment[segment_offset] = (u8)ref->size;
			segment_offset++;
		}

		// Copy data
		void* dest = segment + segment_offset;
		if (ref->copy)
			ref->copy(dest, ref->data, ref->size);
		else
			memcpy(dest, ref->data, ref->size);

		// Set packet as important if at least one segment is important.
		if (ref->important)
			packet->header->flags |= SSP_IMPORTANT_BIT;

        offset += segment_offset + ref->size;
    }

	if (packet->header->flags & SSP_ZSTD_COMPRESSION_BIT)
	{
		u64 compressed_size = ZSTD_compress(
									  packet->payload, 
									  ZSTD_compressBound(packet->payload_size), 
									  payload, 
									  packet->payload_size, 
									  io->tx.compression.level);

		if (ZSTD_isError(compressed_size))
		{
			fprintf(stderr, "ZSTD_compress FAILED: %s\n", ZSTD_getErrorName(compressed_size));
			packet->header->flags ^= SSP_ZSTD_COMPRESSION_BIT;
			memcpy(packet->payload, payload, packet->payload_size);
		}
		else
		{
			printf("SSP Packet payload compressed from %u -> %zu bytes.\n", 
				packet->payload_size, compressed_size);
			ssp_set_header_payload_size(packet, compressed_size);
		}
		free(payload);
	}
}

static void
ssp_serialize(ssp_packet_t* packet, ssp_io_t* io)
{
	ssp_serialize_header(packet, io);
	ssp_serialize_payload(packet, io);
}

static void 
ssp_io_tx_reset(ssp_io_t* io)
{
	if (io == NULL)
        return;

	ssp_ring_reset(&io->tx.ref_ring);
}

ssp_packet_t* 
ssp_io_serialize(ssp_io_t* io)
{
    ssp_packet_t* packet;
	u8 packet_flags = io->tx.flags;
    u32 payload_size;

	if (io->tx.ref_ring.count == 0 && io->rx.acks.min == -1)
        return NULL;

	if (io->rx.acks.min >= 0)
		packet_flags |= SSP_ACK_BIT;

    payload_size = ssp_io_ref_ring_size_f(io, &packet_flags);
    packet = ssp_new_packet(io->ctx, payload_size, packet_flags);

    ssp_serialize(packet, io);

    if (packet->footer)
		packet->footer->checksum = ssp_checksum32(packet->buf, ssp_checksum_size(packet));

	io->tx.total_packets++;

    ssp_io_tx_reset(io);

	if (packet->header->flags & SSP_IMPORTANT_BIT)
		array_add_voidp(&io->tx.pending, packet);

    return packet;
}

void 
ssp_packet_free(ssp_packet_t* packet)
{
	if (packet == NULL)
		return;

	if (packet->header->flags & SSP_IMPORTANT_BIT && packet->last_retry == false)
		return;

	free(packet->buf);
	free(packet);
}

void 
ssp_io_init(ssp_io_t* io, ssp_io_ctx_t* ctx, u8 flags)
{
	io->ctx = ctx;

	io->tx.flags = flags & SSP_USER_FLAGS;
	io->tx.packet_timeout_ms = SSP_DEFAULT_TX_TIMEOUT;
	io->tx.max_rto = 3;
	ssp_ring_init(&io->tx.ref_ring, sizeof(ssp_data_ref_t), MAX_SEGMENT_COUNT);
	array_init(&io->tx.pending, sizeof(ssp_packet_t**), 10);

	io->rx.acks.min = io->rx.acks.max = -1;
	ssp_window_init(&io->rx.window);
}

ssp_data_ref_t*
ssp_io_push_ref(ssp_io_t* io, u8 type, u16 size, const void* data)
{
	/**
	 *	TODO: Check for dups.
	 */

    ssp_data_ref_t* data_ref = ssp_ring_emplace_write(&io->tx.ref_ring);

    data_ref->type = type;
    data_ref->size = size;
    data_ref->data = data;
	data_ref->important = false;
	data_ref->copy = NULL;

	return data_ref;
}

ssp_data_ref_t*
ssp_io_push_ref_i(ssp_io_t* io, u8 type, u16 size, const void* data)
{
	ssp_data_ref_t* data_ref;

	if ((data_ref = ssp_io_push_ref(io, type, size, data)))
		data_ref->important = true;

	return data_ref;
}

ssp_data_ref_t*
ssp_io_push_hook_ref(ssp_io_t* io, u8 type, u16 size, const void* data, ssp_copy_hook_t hook)
{
	ssp_data_ref_t* ref;

	ref = ssp_io_push_ref(io, type, size, data);
	if (ref)
		ref->copy = hook;

	return ref;
}

ssp_data_ref_t*
ssp_io_push_hook_ref_i(ssp_io_t* io, u8 type, u16 size, const void* data, ssp_copy_hook_t hook)
{
	ssp_data_ref_t* ref;

	ref = ssp_io_push_ref_i(io, type, size, data);
	if (ref)
		ref->copy = hook;

	return ref;
}

static void
ssp_io_tx_cleanup_pending(ssp_io_t* io)
{
	for (u32 i = 0; i < io->tx.pending.count; i++)
	{
		ssp_packet_t* packet = ((ssp_packet_t**)io->tx.pending.buf)[i];
		if (packet->header->flags & SSP_IMPORTANT_BIT)
			packet->header->flags ^= SSP_IMPORTANT_BIT;
		ssp_packet_free(packet);
	}
	array_del(&io->tx.pending);
}

static void
ssp_io_rx_cleanup_window(ssp_io_t* io)
{
	for (u32 i = 0; i < SSP_WINDOW_SIZE; i++)
	{
		ssp_packet_t* packet = io->rx.window.window[i];
		ssp_packet_free(packet);
	}
}

void 
ssp_io_deinit(ssp_io_t* io)
{
	ssp_ring_deinit(&io->tx.ref_ring);
	ssp_io_tx_cleanup_pending(io);

	ssp_io_rx_cleanup_window(io);
}

static inline i32
ssp_parse_payload(ssp_io_ctx_t* ctx, const ssp_packet_t* packet, void* source_data)
{
    i32 ret = SSP_SUCCESS;
    u32 offset = 0;
	void* payload;
    ssp_segment_callback_t segment_callback;
    bool segment_called = false;

	if (packet->header->flags & SSP_ZSTD_COMPRESSION_BIT)
	{
		u32 og_size = ZSTD_getFrameContentSize(packet->payload, packet->payload_size);
		payload = malloc(og_size);
		u64 decompress_size = ZSTD_decompress(payload, og_size, packet->payload, packet->payload_size);
		if (ZSTD_isError(decompress_size))
		{
			fprintf(stderr, "ZSTD_decompress FAILED: %s\n", ZSTD_getErrorName(decompress_size));
			free(payload);
			return SSP_FAILED;
		}
		printf("SSP Payload decompressed from: %u -> %zu (og: %u)\n", packet->payload_size, decompress_size, og_size);
	}
	else
		payload = (void*)packet->payload;

    for (u32 i = 0; i < packet->header->segment_count; i++)
    {
		ssp_segment_t segment;
        u8* segment_buf = (u8*)(payload + offset);
		u32 segment_data_offset = 2;

		if (*segment_buf & SSP_SEGMENT_16BIT_PAYLOAD)
		{
			segment.size = *(u16*)(segment_buf + 1);
			*segment_buf ^= SSP_SEGMENT_16BIT_PAYLOAD;
			segment_data_offset++;
		}
		else
			segment.size = (u8)segment_buf[1];

		segment.type = segment_buf[0];
		segment.data = segment_buf + segment_data_offset;
		segment.packet = packet;

        if ((segment_callback = ssp_get_segment_callback(ctx, segment.type)))
        {
            segment_callback(&segment, ctx->user_data, source_data);
            segment_called = true;
        }
        else
            ret = SSP_CALLBACK_NOT_ASSIGN;

        offset += segment.size + segment_data_offset;
    }
	if (packet->header->flags & SSP_ZSTD_COMPRESSION_BIT)
		free(payload);

    return (segment_called) ? ret : SSP_NOT_USED;
}

static inline void
ssp_packet_set_offsets(ssp_packet_t* packet)
{
	u32 offset = sizeof(ssp_header_t);

	if (packet->header->flags & SSP_16_BIT_PAYLOAD_BIT)
	{
		offset += sizeof(u16);
		memcpy(&packet->payload_size, packet->header->payload_size, sizeof(u16));
	}
	else
	{
		offset += sizeof(u8);
		packet->payload_size = *(u8*)packet->header->payload_size;
	}

	if (packet->header->flags & (SSP_SESSION_BIT | SSP_IMPORTANT_BIT | SSP_ACK_BIT))
	{
		packet->opt_data.buf = packet->buf + offset;

		if (packet->header->flags & SSP_SESSION_BIT)
		{
			packet->opt_data.session_id = packet->buf + offset;
			offset += sizeof(u32);
		}

		if (packet->header->flags & SSP_IMPORTANT_BIT)
		{
			packet->opt_data.seq = packet->buf + offset;
			offset += sizeof(u16);
		}

		if (packet->header->flags & SSP_ACK_BIT)
		{
			packet->opt_data.ack_min = packet->buf + offset;
			offset += sizeof(u16);

			packet->opt_data.ack_max = packet->buf + offset;
			offset += sizeof(u16);
		}
	}

	packet->payload = (u8*)packet->buf + offset;
	packet->header_size = offset;
	packet->size = packet->header_size + packet->payload_size;

	if (packet->header->flags & SSP_FOOTER_BIT)
	{
		packet->footer = (ssp_footer_t*)((u8*)packet->payload + packet->payload_size);
		packet->size += sizeof(ssp_footer_t);
	}
}

static inline void 
ssp_handle_incomplete_packet(ssp_packet_t* packet, ssp_io_t* io, u32 buf_size)
{
	if (io)
	{
		io->rx.incomplete.packet.buf = calloc(1, packet->size);
		memcpy(io->rx.incomplete.packet.buf, packet->buf, buf_size);
		io->rx.incomplete.packet.size = packet->size;
		io->rx.incomplete.current_size = buf_size;
	}
	else
		fprintf(stderr, "WARNING: ssp_parse_buf: io is NULL and packet is incomplete!\n");
}

static inline i32 
ssp_packet_checksum(ssp_packet_t* packet)
{
	u32 our_checksum;
	ssp_footer_t* footer;

    if ((footer = packet->footer))
    {
        our_checksum = ssp_checksum32(packet->buf, ssp_checksum_size(packet));
        if (our_checksum != footer->checksum)
		{
			printf("Corrupt packet. Checksum mismatch: 0x%X != 0x%X\n",
					our_checksum, footer->checksum);
            return SSP_FAILED;
		}
    }
	return SSP_SUCCESS;
}

static inline i32 
ssp_handle_session_id(ssp_packet_t* packet, ssp_io_ctx_t* ctx, ssp_io_t** io, void** source_data)
{
	if (ctx->verify_session)
	{
		void* new_source = NULL;
		if (ctx->verify_session(
						*packet->opt_data.session_id, 
						ctx->user_data, 
						*source_data, 
						&new_source, 
						io) == false)
		{
			return SSP_FAILED;
		}
		if (new_source)
			*source_data = new_source;
	}
	else
		return SSP_FAILED;

	return SSP_SUCCESS;
}

static inline enum ssp_parse_status
ssp_handle_seqc(ssp_packet_t* packet, ssp_io_t* io)
{
	enum ssp_parse_status ret = SSP_PARSE_DO_IMMEDIATELY;

	if (io)
	{
		const u16 new_seq = *packet->opt_data.seq;
		const u16 esn = io->rx.window.next_seq;

		if (new_seq == esn)
		{
			ssp_window_add_packet(&io->rx.window, packet);
			ret = SSP_PARSE_BUFFERED;
		}
		else if (new_seq < esn)
		{
			ret = SSP_PARSE_DROPPED;
		}
		else 
		{
			if (new_seq < esn + SSP_WINDOW_SIZE)
			{
				ssp_window_add_packet(&io->rx.window, packet);
				ret = SSP_PARSE_BUFFERED;
			}
			else
			{
				/**
				 * Sequence count too large. It probably high jitter from sender. 
				 * discard all buffered packets and slide window.
				 */
				printf("ssp: new_seq too large! Sliding window: %u -> %u\n", esn, new_seq);
				ssp_slide_window(&io->rx.window, new_seq);
				ssp_window_add_packet(&io->rx.window, packet);
				ret = SSP_PARSE_BUFFERED;
			}
		}

		if (io->rx.acks.min == -1 || new_seq < io->rx.acks.min)
			io->rx.acks.min = new_seq;
		if (new_seq > io->rx.acks.max)
			io->rx.acks.max = new_seq;
	}
	else
		return SSP_PARSE_FAILED;	// We cant send ACK if no io.
	
	return ret;
}

static inline void
ssp_handle_ack(ssp_packet_t* packet, ssp_io_t* io)
{
	if (io)
	{
		const u16 min = *packet->opt_data.ack_min;
		const u16 max = *packet->opt_data.ack_max;

		for (u32 i = 0; i < io->tx.pending.count; i++)
		{
			ssp_packet_t* imp_packet = ((ssp_packet_t**)io->tx.pending.buf)[i];
			const u16 seq = *imp_packet->opt_data.seq;

			if (seq >= min && seq <= max)
			{
				imp_packet->header->flags ^= SSP_IMPORTANT_BIT;
				ssp_packet_free(imp_packet);
				array_erase(&io->tx.pending, i);
				i--;
			}
		}
	}
	else
		printf("ssp: SSP_ACK_BIT but no io...\n");
}

static inline enum ssp_parse_status
ssp_parse_opt_data(ssp_packet_t* packet, ssp_io_ctx_t* ctx, ssp_io_t** io, void** source_data)
{
	enum ssp_parse_status status = SSP_PARSE_DO_IMMEDIATELY;

	if (packet->opt_data.session_id)
	{
		if (ssp_handle_session_id(packet, ctx, io, source_data) != SSP_SUCCESS)
			return SSP_PARSE_FAILED;
	}

	if (packet->opt_data.seq)
	{
		if ((status = ssp_handle_seqc(packet, *io)) == SSP_PARSE_FAILED)
			return status;
	}

	if (packet->opt_data.ack_min)
		ssp_handle_ack(packet, *io);

	return status;
}

static enum ssp_parse_status
ssp_parse_header(ssp_packet_t* packet, ssp_io_ctx_t* ctx, ssp_io_t** io, void* buf, u32 buf_size, void** source_data)
{
	packet->buf = packet->header = buf;

	/* First check magic ID */
    if (packet->header->magic != ctx->magic)
		return SSP_PARSE_FAILED;

	/* Set offset pointers to buffer */
	ssp_packet_set_offsets(packet);

    if (packet->size > buf_size)
    {
		ssp_handle_incomplete_packet(packet, *io, buf_size);
		return SSP_PARSE_BUFFERED;
	}

	if (ssp_packet_checksum(packet) == SSP_FAILED)
		return SSP_PARSE_FAILED;

	return ssp_parse_opt_data(packet, ctx, io, source_data);
}

i32
ssp_io_process_window(ssp_io_t* io, void* source_data)
{
	i32 ret = SSP_SUCCESS;
	const ssp_packet_t* packet;

	while ((packet = ssp_window_get_packet(&io->rx.window, io->ctx->current_time)))
	{
		ret = ssp_parse_payload(io->ctx, packet, source_data);

		packet->header->flags ^= SSP_IMPORTANT_BIT;
		ssp_packet_free((void*)packet);
	}

	return ret;
}

i32
ssp_io_process(ssp_io_process_params_t* params)
{
	ssp_io_ctx_t* ctx = params->ctx;
	ssp_io_t* io = params->io;
	if (io && ctx == NULL)
		ctx = io->ctx;
	void* buf = params->buf;
	u32   buf_size = params->size;

	i32 ret = SSP_SUCCESS;
	enum ssp_parse_status status;
    ssp_packet_t* packet;

	if (io && io->rx.incomplete.packet.buf)
	{
		memcpy((u8*)io->rx.incomplete.packet.buf + io->rx.incomplete.current_size, buf, buf_size);
		io->rx.incomplete.current_size += buf_size;

		if (io->rx.incomplete.current_size < io->rx.incomplete.packet.size)
			return SSP_INCOMPLETE;

		buf = io->rx.incomplete.packet.buf;
		buf_size = io->rx.incomplete.current_size;
		io->rx.incomplete.current_size = io->rx.incomplete.packet.size = 0;
	}

	packet = calloc(1, sizeof(ssp_packet_t));
	packet->timestamp = params->timestamp_s;
	status = ssp_parse_header(packet, ctx, &io, buf, buf_size, &params->peer_data);

	switch (status)
	{
		case SSP_PARSE_DO_IMMEDIATELY:
			ret = ssp_parse_payload(ctx, packet, params->peer_data);
			break;
		case SSP_PARSE_BUFFERED:
		{
			ssp_io_process_window(io, params->peer_data);
			ret = SSP_BUFFERED;
			break;
		}
		case SSP_PARSE_FAILED:
		{
			ret = SSP_FAILED;
			if (io)
				io->rx.dropped_packets++;
			break;
		}
		case SSP_PARSE_DROPPED:
		{
			ret = SSP_NOT_USED;
			if (io)
				io->rx.dropped_packets++;
			break;
		}
		default:
			if (io)
				io->rx.dropped_packets++;
			break;
	}

	if (status != SSP_PARSE_BUFFERED)
		free(packet);

	if (io)
	{
		io->rx.total_packets++;

		if (io->rx.incomplete.packet.buf && io->rx.incomplete.packet.size == 0)
		{
			free(io->rx.incomplete.packet.buf);
			memset(&io->rx.incomplete.packet, 0, sizeof(ssp_packet_t));
		}
	}

    return ret;
}

ssp_packet_t* 
ssp_io_find_expired_packet(ssp_io_t* io, f64 current_time)
{
	for (u32 i = 0; i < io->tx.pending.count; i++)
	{
		ssp_packet_t* imp_packet = ((ssp_packet_t**)io->tx.pending.buf)[i];
		f32 elapsed_time_ms = (current_time - imp_packet->timestamp) * 1000;

		if (elapsed_time_ms >= io->tx.packet_timeout_ms)
		{
			imp_packet->timestamp = current_time;
			imp_packet->retries++;

			if (imp_packet->retries >= io->tx.max_rto)
			{
				imp_packet->last_retry = true;
				array_erase(&io->tx.pending, i);
			}
			io->tx.rto++;

			return imp_packet;
		}
	}
	return NULL;
}

void
ssp_io_set_rtt(ssp_io_t* io, f32 rtt_ms)
{
	f32 new_window_interval = rtt_ms + SSP_WINDOW_TIMEOUT_MARGIN_MS;

	if (new_window_interval >= SSP_WINDOW_TIMEOUT_MARGIN_MS)
		io->rx.window.timeout_ms = new_window_interval;

	f32 new_interval = rtt_ms + RESEND_SAFETY_MARGIN_MS;

	if (new_interval >= RESEND_SAFETY_MARGIN_MS)
		io->tx.packet_timeout_ms = new_interval;
}
