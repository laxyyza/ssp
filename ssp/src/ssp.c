#define _GNU_SOURCE
#include "ssp.h"
#include <string.h>
#include <stdio.h>
#include <zstd.h>

#define SSP_MAX_ACKS 64
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

static u32 ssp_magic = SSP_MAGIC;

static inline u64
ssp_addr_diff(void* base, void* offset)
{
	return ((u64)offset) - ((u64)base);
}

static inline bool
ssp_is_seq_newer(u16 current_seq, u16 ref_seq)
{
	return ((current_seq - ref_seq) & SEQ_MASK) < SEQ_HALF;
}

static inline bool
ssp_is_seq_older(u16 current_seq, u16 ref_seq)
{
	return !ssp_is_seq_newer(current_seq, ref_seq) && current_seq != ref_seq;
}

void 
ssp_ctx_init(ssp_ctx_t* ctx)
{
    ght_init(&ctx->segment_callbacks, 10, NULL);
}

void 
ssp_set_magic(u32 magic)
{
	ssp_magic = magic;
}

void 
ssp_ctx_destroy(ssp_ctx_t* ctx)
{
	ght_destroy(&ctx->segment_callbacks);
}

void 
ssp_segment_callback(ssp_ctx_t* ctx, u16 segtype, ssp_segment_callback_t callback)
{
    ght_insert(&ctx->segment_callbacks, segtype, callback);
}

static inline ssp_segment_callback_t 
ssp_get_segment_callback(ssp_ctx_t* ctx, u16 segtype)
{
    return ght_get(&ctx->segment_callbacks, segtype);
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

ssp_packet_t*
ssp_new_packet(u32 payload_size, u8 flags)
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
    packet->header->magic = ssp_magic;
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

u32 
ssp_segbuf_serialized_size(const ssp_segbuf_t* segbuf, u8* flags)
{
    u32 total = 0;

    for (u32 i = 0; i < segbuf->count; i++)
	{
		u16 data_size = segbuf->data_refs[i].size;
        total += data_size + 1;			// +1 is for type.
		if (data_size >= UINT8_MAX)
			total += sizeof(u16);
		else
			total += sizeof(u8);

		if (flags && segbuf->data_refs[i].important)
			*flags |= SSP_IMPORTANT_BIT;
	}

	if (total == 0 && *flags & SSP_IMPORTANT_BIT)
		*flags ^= SSP_IMPORTANT_BIT;

    return total;
}

static void
ssp_serialize_header(ssp_packet_t* packet, ssp_segbuf_t* segbuf)
{
	u32 offset = 0;

	packet->header->segment_count = segbuf->count;

	if (packet->opt_data.buf == NULL)
		return;

	if (packet->header->flags & SSP_SESSION_BIT)
	{
		packet->opt_data.session_id = packet->opt_data.buf + offset;
		*packet->opt_data.session_id = segbuf->session_id;
		offset += sizeof(u32);
	}

	if (packet->header->flags & SSP_IMPORTANT_BIT)
	{
		packet->opt_data.seq = packet->opt_data.buf + offset;
		*packet->opt_data.seq = ++segbuf->seqc_sent;
		offset += sizeof(u16);
	}

	if (packet->header->flags & SSP_ACK_BIT)
	{
		packet->opt_data.ack_min = packet->opt_data.buf + offset;
		offset += sizeof(u16);

		packet->opt_data.ack_max = packet->opt_data.buf + offset;
		offset += sizeof(u16);

		*packet->opt_data.ack_min = (u16)segbuf->acks.min;
		*packet->opt_data.ack_max = (u16)segbuf->acks.max;

		segbuf->acks.min = segbuf->acks.max = -1;
	}
}

static void 
ssp_serialize_payload(ssp_packet_t* packet, ssp_segbuf_t* segbuf)
{
	u32 offset = 0;
	void* payload;

	if (packet->payload_size == 0)
		return;

	if (packet->header->flags & SSP_ZSTD_COMPRESSION_BIT || 
		(segbuf->compression.auto_do && packet->payload_size > segbuf->compression.threshold))
	{
		payload = malloc(packet->size);
		packet->header->flags |= SSP_ZSTD_COMPRESSION_BIT;
	}
	else
		payload = packet->payload;

    for (u32 i = 0; i < segbuf->count; i++)
    {
		u32 segment_offset = 0;
        const ssp_data_ref_t* data_ref = segbuf->data_refs + i;
        u8* segment = payload + offset;

		// We are assuming type is less than 127.
		segment[segment_offset] = data_ref->type;
		segment_offset++;

		if (data_ref->size >= UINT8_MAX)
		{
			// Set data size (16-bit)
			*segment |= SSP_SEGMENT_16BIT_PAYLOAD;
			*(u16*)&segment[segment_offset] = data_ref->size; 
			segment_offset += sizeof(u16);
		}
		else
		{
			// Set data size
			segment[segment_offset] = (u8)data_ref->size;
			segment_offset++;
		}

		// Copy data
		memcpy(segment + segment_offset, data_ref->data, data_ref->size);

		// Set packet as important if at least one segment is important.
		if (data_ref->important)
			packet->header->flags |= SSP_IMPORTANT_BIT;

        offset += segment_offset + data_ref->size;
    }

	if (packet->header->flags & SSP_ZSTD_COMPRESSION_BIT)
	{
		u64 compressed_size = ZSTD_compress(
									  packet->payload, 
									  ZSTD_compressBound(packet->payload_size), 
									  payload, 
									  packet->payload_size, 
									  segbuf->compression.level);

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
ssp_serialize(ssp_packet_t* packet, ssp_segbuf_t* segbuf)
{
	ssp_serialize_header(packet, segbuf);
	ssp_serialize_payload(packet, segbuf);
}

ssp_packet_t* 
ssp_serialize_packet(ssp_segbuf_t* segbuf)
{
    ssp_packet_t* packet;
	u8 packet_flags = segbuf->flags;
    u32 payload_size;

	if (segbuf->count == 0 && segbuf->acks.min == -1)
        return NULL;

	if (segbuf->acks.min >= 0)
		packet_flags |= SSP_ACK_BIT;

    payload_size = ssp_segbuf_serialized_size(segbuf, &packet_flags);
    packet = ssp_new_packet(payload_size, packet_flags);

    ssp_serialize(packet, segbuf);

    if (packet->footer)
		packet->footer->checksum = ssp_checksum32(packet->buf, ssp_checksum_size(packet));

    ssp_segbuf_clear(segbuf);

	if (packet->header->flags & SSP_IMPORTANT_BIT)
		array_add_voidp(&segbuf->important_packets, packet);

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

ssp_packet_t* 
ssp_insta_packet(ssp_segbuf_t* source_segbuf, u16 type, const void* buf, u64 size)
{
	ssp_packet_t* ret;
	ssp_data_ref_t segment_ref = {
		.data = buf,
		.size = size,
		.type = type
	};
	ssp_segbuf_t segbuf = {
		.count = 1,
		.size = 1,
		.min_size = 1,
		.session_id = source_segbuf->session_id,
		.flags = source_segbuf->flags,
		.seqc_sent = source_segbuf->seqc_sent,
		.data_refs = &segment_ref,
		.acks = source_segbuf->acks
	};

	if (segbuf.flags & SSP_IMPORTANT_BIT)
		segbuf.flags ^= SSP_IMPORTANT_BIT;

	ret = ssp_serialize_packet(&segbuf);
	source_segbuf->seqc_sent = segbuf.seqc_sent;
	source_segbuf->acks = segbuf.acks;

	return ret;
}

void 
ssp_segbuf_init(ssp_segbuf_t* segbuf, u32 init_size, u8 flags)
{
    segbuf->data_refs = calloc(init_size, sizeof(ssp_data_ref_t));
    segbuf->size = init_size;
    segbuf->count = 0;
    segbuf->min_size = init_size;
    segbuf->inc_size = init_size;
	segbuf->flags = flags;
	segbuf->retry_interval_ms = 300.0;
	segbuf->max_retries = 3;
	segbuf->acks.max = segbuf->acks.min = -1;

	ssp_window_init(&segbuf->sliding_window);
	array_init(&segbuf->important_packets, sizeof(ssp_packet_t**), SSP_MAX_ACKS);
}

void 
ssp_segbuf_resize(ssp_segbuf_t* segbuf, u32 new_size)
{
    if (new_size < segbuf->min_size)
        new_size = segbuf->min_size;
    if (new_size == segbuf->size)
        return;

    segbuf->data_refs = realloc(segbuf->data_refs, new_size * sizeof(ssp_data_ref_t));
    segbuf->size = new_size;
}

ssp_data_ref_t*
ssp_segbuf_add(ssp_segbuf_t* segbuf, u8 type, u16 size, const void* data)
{
    for (u32 i = 0; i < segbuf->count; i++)
	{
        const ssp_data_ref_t* data_ref = segbuf->data_refs + i;
		if (data_ref->data == data && data_ref->size == size)
			return NULL; // Dont duplicate data.
	}

    ssp_data_ref_t* data_ref = segbuf->data_refs + segbuf->count;
    data_ref->type = type;
    data_ref->size = size;
    data_ref->data = data;
	data_ref->important = false;
    segbuf->count++;

	if (segbuf->count >= segbuf->size)
        ssp_segbuf_resize(segbuf, segbuf->size + segbuf->inc_size);

	return data_ref;
}

void 
ssp_segbuf_add_i(ssp_segbuf_t* segbuf, u8 type, u16 size, const void* data)
{
	ssp_data_ref_t* data_ref;

	if ((data_ref = ssp_segbuf_add(segbuf, type, size, data)))
		data_ref->important = true;
}

void 
ssp_segbuf_clear(ssp_segbuf_t* segbuf)
{
    if (segbuf == NULL)
        return;

    segbuf->count = 0;
    ssp_segbuf_resize(segbuf, segbuf->min_size);
}

static void
ssp_segbuf_cleanup_imp_packets(ssp_segbuf_t* segbuf)
{
	for (u32 i = 0; i < segbuf->important_packets.count; i++)
	{
		ssp_packet_t* packet = ((ssp_packet_t**)segbuf->important_packets.buf)[i];
		ssp_packet_free(packet);
	}
	array_del(&segbuf->important_packets);
}

static void
ssp_segbuf_cleanup_window(ssp_segbuf_t* segbuf)
{
	for (u32 i = 0; i < SSP_WINDOW_SIZE; i++)
	{
		ssp_packet_t* packet = segbuf->sliding_window.window[i];
		ssp_packet_free(packet);
	}
}

void 
ssp_segbuf_destroy(ssp_segbuf_t* segbuf)
{
	ssp_segbuf_cleanup_window(segbuf);
	free(segbuf->data_refs);
	ssp_segbuf_cleanup_imp_packets(segbuf);
}

static inline i32
ssp_parse_payload(ssp_ctx_t* ctx, const ssp_packet_t* packet, void* source_data)
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
ssp_handle_incomplete_packet(ssp_packet_t* packet, ssp_segbuf_t* segbuf, u32 buf_size)
{
	if (segbuf)
	{
		segbuf->recv_incomplete.packet.buf = calloc(1, packet->size);
		memcpy(segbuf->recv_incomplete.packet.buf, packet->buf, buf_size);
		segbuf->recv_incomplete.packet.size = packet->size;
		segbuf->recv_incomplete.current_size = buf_size;
	}
	else
		fprintf(stderr, "WARNING: ssp_parse_buf: segbuf is NULL and packet is incomplete!\n");
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
ssp_handle_session_id(ssp_packet_t* packet, ssp_ctx_t* ctx, ssp_segbuf_t** segbuf, void** source_data)
{
	if (ctx->verify_session)
	{
		void* new_source = NULL;
		if (ctx->verify_session(
						*packet->opt_data.session_id, 
						ctx->user_data, 
						*source_data, 
						&new_source, 
						segbuf) == false)
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
ssp_handle_seqc(ssp_packet_t* packet, ssp_segbuf_t* segbuf)
{
	enum ssp_parse_status ret = SSP_PARSE_DO_IMMEDIATELY;

	if (segbuf)
	{
		const u16 new_seq = *packet->opt_data.seq;
		const u16 esn = segbuf->sliding_window.next_seq;

		if (new_seq == esn)
		{
			ssp_window_add_packet(&segbuf->sliding_window, packet);
			ret = SSP_PARSE_BUFFERED;
		}
		else if (new_seq < esn)
		{
			printf("Outdated or duplicate packet: seq:%u, esn:%u\n", new_seq, esn);
			ret = SSP_PARSE_DROPPED;
		}
		else 
		{
			if (new_seq < esn + SSP_WINDOW_SIZE)
			{
				ssp_window_add_packet(&segbuf->sliding_window, packet);
				ret = SSP_PARSE_BUFFERED;
			}
			else
			{
				/**
				 * Sequence count too large. It probably high jitter from sender. 
				 * discard all buffered packets and slide window.
				 */
				printf("ssp: new_seq too large! Sliding window: %u -> %u\n", esn, new_seq);
				ssp_slide_window(&segbuf->sliding_window, new_seq);
				ssp_window_add_packet(&segbuf->sliding_window, packet);
				ret = SSP_PARSE_BUFFERED;
			}
		}

		if (segbuf->acks.min == -1 || new_seq < segbuf->acks.min)
			segbuf->acks.min = new_seq;
		if (new_seq > segbuf->acks.max)
			segbuf->acks.max = new_seq;
	}
	else
		return SSP_PARSE_FAILED;	// We cant send ACK if no segbuf.
	
	return ret;
}

static inline void
ssp_handle_ack(ssp_packet_t* packet, ssp_segbuf_t* segbuf)
{
	if (segbuf)
	{
		const u16 min = *packet->opt_data.ack_min;
		const u16 max = *packet->opt_data.ack_max;

		for (u32 i = 0; i < segbuf->important_packets.count; i++)
		{
			ssp_packet_t* imp_packet = ((ssp_packet_t**)segbuf->important_packets.buf)[i];
			const u16 seq = *imp_packet->opt_data.seq;

			if (seq >= min && seq <= max)
			{
				imp_packet->header->flags ^= SSP_IMPORTANT_BIT;
				ssp_packet_free(imp_packet);
				array_erase(&segbuf->important_packets, i);
				i--;
			}
		}
	}
	else
		printf("ssp: SSP_ACK_BIT but no segbuf...\n");
}

static inline enum ssp_parse_status
ssp_parse_opt_data(ssp_packet_t* packet, ssp_ctx_t* ctx, ssp_segbuf_t** segbuf, void** source_data)
{
	enum ssp_parse_status status = SSP_PARSE_DO_IMMEDIATELY;

	if (packet->opt_data.session_id)
	{
		if (ssp_handle_session_id(packet, ctx, segbuf, source_data) != SSP_SUCCESS)
			return SSP_PARSE_FAILED;
	}

	if (packet->opt_data.seq)
	{
		if ((status = ssp_handle_seqc(packet, *segbuf)) == SSP_PARSE_FAILED)
			return status;
	}

	if (packet->opt_data.ack_min)
		ssp_handle_ack(packet, *segbuf);

	return status;
}

static enum ssp_parse_status
ssp_parse_header(ssp_packet_t* packet, ssp_ctx_t* ctx, ssp_segbuf_t** segbuf, void* buf, u32 buf_size, void** source_data)
{
	packet->buf = packet->header = buf;

	/* First check magic ID */
    if (packet->header->magic != ssp_magic)
		return SSP_PARSE_FAILED;

	/* Set offset pointers to buffer */
	ssp_packet_set_offsets(packet);

    if (packet->size > buf_size)
    {
		ssp_handle_incomplete_packet(packet, *segbuf, buf_size);
		return SSP_PARSE_BUFFERED;
	}

	if (ssp_packet_checksum(packet) == SSP_FAILED)
		return SSP_PARSE_FAILED;

	return ssp_parse_opt_data(packet, ctx, segbuf, source_data);
}

i32
ssp_parse_sliding_window(ssp_ctx_t* ctx, ssp_segbuf_t* segbuf, void* source_data)
{
	i32 ret = SSP_SUCCESS;
	const ssp_packet_t* packet;

	while ((packet = ssp_window_get_packet(&segbuf->sliding_window, ctx->current_time)))
	{
		ret = ssp_parse_payload(ctx, packet, source_data);

		packet->header->flags ^= SSP_IMPORTANT_BIT;
		ssp_packet_free((void*)packet);
	}

	return ret;
}

i32
ssp_parse_buf(ssp_ctx_t* ctx, ssp_segbuf_t* segbuf, void* buf, u32 buf_size, void* source_data)
{
	i32 ret = SSP_SUCCESS;
	enum ssp_parse_status status;
    ssp_packet_t* packet;

	if (segbuf && segbuf->recv_incomplete.packet.buf)
	{
		memcpy((u8*)segbuf->recv_incomplete.packet.buf + segbuf->recv_incomplete.current_size, buf, buf_size);
		segbuf->recv_incomplete.current_size += buf_size;

		if (segbuf->recv_incomplete.current_size < segbuf->recv_incomplete.packet.size)
			return SSP_INCOMPLETE;

		buf = segbuf->recv_incomplete.packet.buf;
		buf_size = segbuf->recv_incomplete.current_size;
		segbuf->recv_incomplete.current_size = segbuf->recv_incomplete.packet.size = 0;
	}

	packet = calloc(1, sizeof(ssp_packet_t));
	packet->timestamp = ctx->current_time;
	status = ssp_parse_header(packet, ctx, &segbuf, buf, buf_size, &source_data);

	switch (status)
	{
		case SSP_PARSE_DO_IMMEDIATELY:
			ret = ssp_parse_payload(ctx, packet, source_data);
			break;
		case SSP_PARSE_BUFFERED:
		{
			ssp_parse_sliding_window(ctx, segbuf, source_data);
			ret = SSP_BUFFERED;
			break;
		}
		case SSP_PARSE_FAILED:
			ret = SSP_FAILED;
			break;
		case SSP_PARSE_DROPPED:
			ret = SSP_NOT_USED;
			break;
		default:
			break;
	}

	if (status != SSP_PARSE_BUFFERED)
		free(packet);

	if (segbuf && segbuf->recv_incomplete.packet.buf && segbuf->recv_incomplete.packet.size == 0)
	{
		free(segbuf->recv_incomplete.packet.buf);
		memset(&segbuf->recv_incomplete.packet, 0, sizeof(ssp_packet_t));
	}

    return ret;
}

ssp_packet_t* 
ssp_segbuf_get_resend_packet(ssp_segbuf_t* segbuf, f64 current_time)
{
	for (u32 i = 0; i < segbuf->important_packets.count; i++)
	{
		ssp_packet_t* imp_packet = ((ssp_packet_t**)segbuf->important_packets.buf)[i];
		f32 elapsed_time_ms = (current_time - imp_packet->timestamp) * 1000;

		if (elapsed_time_ms >= segbuf->retry_interval_ms)
		{
			imp_packet->timestamp = current_time;
			imp_packet->retries++;

			if (imp_packet->retries >= segbuf->max_retries)
			{
				imp_packet->last_retry = true;
				array_erase(&segbuf->important_packets, i);
			}

			return imp_packet;
		}
	}
	return NULL;
}

void
ssp_segbuf_set_rtt(ssp_segbuf_t* segbuf, f32 rtt_ms)
{
	f32 new_window_interval = rtt_ms + SSP_WINDOW_TIMEOUT_MARGIN_MS;

	if (new_window_interval >= SSP_WINDOW_TIMEOUT_MARGIN_MS)
		segbuf->sliding_window.timeout_ms = new_window_interval;

	f32 new_interval = rtt_ms + RESEND_SAFETY_MARGIN_MS;

	if (new_interval >= RESEND_SAFETY_MARGIN_MS)
		segbuf->retry_interval_ms = new_interval;
}
