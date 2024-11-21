#define _GNU_SOURCE
#include "ssp.h"
#include <string.h>
#include <stdio.h>
#include <zstd.h>
#include <time.h>

#define SSP_MAX_ACKS 8
#define RESEND_SAFETY_MARGIN_MS 50
#define SEQ_HALF (1 << 15)
#define SEQ_MASK 0xFFFF

static u32 ssp_magic = SSP_MAGIC;

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
	if (flags & SSP_SEQUENCE_COUNT_BIT)
		header_size += sizeof(u16);	// +2 bytes
	if (flags & SSP_ACK_BIT)
		header_size += sizeof(u16); // +2 bytes

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

    return total;
}

static void 
ssp_bytes_name(const u8* buf, u32 count, u32 tab_count, const char* name)
{
	if (tab_count == 0)
		tab_count = 1;

	printf("\t\t");

	for (u32 i = 0; i < count; i++)
		printf("%.2X ", buf[i]);

	for (u32 i = 0; i < tab_count; i++)
		printf("\t");

	if (count == sizeof(u8))
		printf("(%u)", *buf);
	else if (count == sizeof(u16))
		printf("(%u)", *(u16*)buf);
	else if (count == sizeof(u32))
		printf("(%u)", *(u32*)buf);

	for (u32 i = 0; i < tab_count; i++)
		printf("\t");

	printf("%s\n", name);
}

void
ssp_print_packet(ssp_ctx_t* ctx, const ssp_packet_t* packet, const u8* payload)
{
	const u8* buf = packet->buf;
	u32 offset = 0;
	u32 payload_size;

	printf("\n---[SSP Packet. Size: %u, Payload: %u]---\n{\n\t", 
		packet->size, packet->payload_size);

	printf("-[SSP Header]-\n\t{\n");
	ssp_bytes_name(buf + offset, sizeof(u32), 1, "SSP_MAGIC");
	offset += sizeof(u32);

#define FLAGS_NAME_LEN 256
#define SEGMENT_DATA_MAX 16

	char flags_name[FLAGS_NAME_LEN] = "FLAGS (";
	if (packet->header->flags & SSP_FOOTER_BIT)
		strcat(flags_name, "SSP_FOOTER_BIT | ");
	if (packet->header->flags & SSP_SESSION_BIT)
		strcat(flags_name, "SSP_SESSION_BIT | ");
	if (packet->header->flags & SSP_SEQUENCE_COUNT_BIT)
		strcat(flags_name, "SSP_SEQUENCE_COUNT_BIT | ");
	if (packet->header->flags & SSP_ZSTD_COMPRESSION_BIT)
		strcat(flags_name, "SSP_ZSTD_COMPRESSION_BIT | ");
	if (packet->header->flags & SSP_16_BIT_PAYLOAD_BIT)
		strcat(flags_name, "SSP_16_BIT_PAYLOAD_BIT | ");

	flags_name[strlen(flags_name) - 3] = 0x00;

	strcat(flags_name, ")");

	ssp_bytes_name(buf + offset, sizeof(u8), 2, flags_name);
	offset += sizeof(u8);
	ssp_bytes_name(buf + offset, sizeof(u8), 2, "SEGMENT_COUNT");
	offset += sizeof(u8);

	if (packet->header->flags & SSP_16_BIT_PAYLOAD_BIT)
		payload_size = sizeof(u16);
	else
		payload_size = sizeof(u8);

	ssp_bytes_name(buf + offset, payload_size, 2, "PAYLOAD_SIZE");
	offset = 0;
	buf = payload;

	printf("\t}\n\t-[SSP Payload]-\n\t}\n");
	if (packet->header->flags & SSP_SESSION_BIT)
	{
		ssp_bytes_name(buf + offset, sizeof(u32), 1, "SSP_SESSION_BIT");
		offset += sizeof(u32);
	}
	if (packet->header->flags & SSP_SEQUENCE_COUNT_BIT)
	{
		ssp_bytes_name(buf + offset, sizeof(u16), 2, "SSP_SEQUENCE_COUNT_BIT");
		offset += sizeof(u16);
	}

	for (u32 i = 0; i < packet->header->segment_count; i++)
	{
		printf("\t\t-[SSP Segment %u]-\n\t\t{\n\t", i);
		u8 segment_type = buf[offset];
		u32 segment_payload_size;
		u32 segment_size;
		bool _16bit_size = false;

		char segment_type_str[FLAGS_NAME_LEN];
		snprintf(segment_type_str, FLAGS_NAME_LEN, "TYPE \"%s\"", (ctx->segment_type_str) ? ctx->segment_type_str(segment_type) : "");

		if (segment_type & SSP_SEGMENT_16BIT_PAYLOAD)
		{
			strcat(segment_type_str, " (SSP_SEGMENT_16BIT_PAYLOAD)");
			((u8*)buf)[offset] ^= SSP_SEGMENT_16BIT_PAYLOAD;
			_16bit_size = true;
		}

		ssp_bytes_name(buf + offset, sizeof(u8), 1, segment_type_str);
		offset += sizeof(u8);

		if (_16bit_size)
		{
			segment_payload_size = sizeof(u16);
			((u8*)buf)[offset - 1] ^= SSP_SEGMENT_16BIT_PAYLOAD;
			segment_size = *(u16*)(buf + offset);
		}
		else
		{
			segment_payload_size = sizeof(u8);
			segment_size = *(buf + offset);
		}

		printf("\t");
		ssp_bytes_name(buf + offset, segment_payload_size, 1, "SEGMENT_SIZE");
		offset += segment_payload_size;

		printf("\t\t\t[ ");
		for (u32 j = 0; j < ((segment_size > SEGMENT_DATA_MAX) ? SEGMENT_DATA_MAX : segment_size); j++)
		{
			printf("%.2X ", payload[offset + j]);
		}
		if (segment_size > SEGMENT_DATA_MAX)
			printf("... ");
		printf("]\n");

		offset += segment_size;

		printf("\t\t}\n");
	}

	printf("\t}\n}\n");
}

static void
ssp_serialize_header(ssp_packet_t* packet, ssp_segbuf_t* segbuf)
{
	u32 offset = 0;
	u16 ack;

	packet->header->segment_count = segbuf->count;

	if (packet->opt_data.buf == NULL)
		return;

	if (packet->header->flags & SSP_SESSION_BIT)
	{
		packet->opt_data.session_id = packet->opt_data.buf + offset;
		*packet->opt_data.session_id = segbuf->session_id;
		offset += sizeof(u32);
	}

	if (packet->header->flags & SSP_SEQUENCE_COUNT_BIT)
	{
		packet->opt_data.seq = packet->opt_data.buf + offset;
		*packet->opt_data.seq = ++segbuf->seqc_sent;
		offset += sizeof(u16);
	}

	if (ssp_ring_read_u16(&segbuf->acks, &ack))
	{
		packet->opt_data.ack = packet->opt_data.buf + offset;
		*packet->opt_data.ack = ack;
		offset += sizeof(u16);
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

	if (segbuf->count == 0 && segbuf->acks.count == 0)
        return NULL;

	if (segbuf->acks.count)
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
		.data_refs = &segment_ref
	};

	ret = ssp_serialize_packet(&segbuf);
	source_segbuf->seqc_sent = segbuf.seqc_sent;

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

	ssp_ring_init(&segbuf->acks, sizeof(u16), SSP_MAX_ACKS);
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

void 
ssp_segbuf_destroy(ssp_segbuf_t* segbuf)
{
	free(segbuf->data_refs);
	array_del(&segbuf->important_packets);
	ssp_ring_free(&segbuf->acks);
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

	if (ctx->debug)
		ssp_print_packet(ctx, packet, payload);

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

	if (packet->header->flags & (SSP_SESSION_BIT | SSP_SEQUENCE_COUNT_BIT | SSP_ACK_BIT))
	{
		packet->opt_data.buf = packet->buf + offset;

		if (packet->header->flags & SSP_SESSION_BIT)
		{
			packet->opt_data.session_id = packet->buf + offset;
			offset += sizeof(u32);
		}

		if (packet->header->flags & SSP_SEQUENCE_COUNT_BIT)
		{
			packet->opt_data.seq = packet->buf + offset;
			offset += sizeof(u16);
		}

		if (packet->header->flags & SSP_ACK_BIT)
		{
			packet->opt_data.ack = packet->buf + offset;
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

static inline i32
ssp_handle_seqc(ssp_packet_t* packet, ssp_segbuf_t* segbuf)
{
	if (segbuf)
	{
		// TODO: Implement reordering.
		
		if (packet->header->flags & SSP_IMPORTANT_BIT)
			ssp_ring_write_u16(&segbuf->acks, *packet->opt_data.seq);

		segbuf->last_seqc_recv = *packet->opt_data.seq;
	}
	else if (packet->header->flags & SSP_IMPORTANT_BIT)
		return SSP_FAILED;	// We cant send ACK if no segbuf.
	
	return SSP_SUCCESS;
}

static inline void
ssp_handle_ack(ssp_packet_t* packet, ssp_segbuf_t* segbuf)
{
	if (segbuf)
	{
		for (u32 i = 0; i < segbuf->important_packets.count; i++)
		{
			ssp_packet_t* imp_packet = ((ssp_packet_t**)segbuf->important_packets.buf)[i];

			if (*imp_packet->opt_data.seq == *packet->opt_data.ack)
			{
				imp_packet->header->flags ^= SSP_IMPORTANT_BIT;
				ssp_packet_free(imp_packet);
				array_erase(&segbuf->important_packets, i);
				break;
			}
		}
	}
	else
		printf("ssp: SSP_ACK_BIT but no segbuf...\n");
}

static inline i32
ssp_parse_opt_data(ssp_packet_t* packet, ssp_ctx_t* ctx, ssp_segbuf_t** segbuf, void** source_data)
{
	if (packet->opt_data.session_id)
	{
		if (ssp_handle_session_id(packet, ctx, segbuf, source_data) != SSP_SUCCESS)
			return SSP_FAILED;
	}

	if (packet->opt_data.seq)
	{
		if (ssp_handle_seqc(packet, *segbuf) != SSP_SUCCESS)
			return SSP_FAILED;
	}

	if (packet->opt_data.ack)
		ssp_handle_ack(packet, *segbuf);

	return SSP_SUCCESS;
}

static i32
ssp_parse_header(ssp_packet_t* packet, ssp_ctx_t* ctx, ssp_segbuf_t** segbuf, void* buf, u32 buf_size, void** source_data)
{
	memset(packet, 0, sizeof(ssp_packet_t));
	packet->buf = packet->header = buf;

	/* First check magic ID */
    if (packet->header->magic != ssp_magic)
		return SSP_FAILED;

	/* Set offset pointers to buffer */
	ssp_packet_set_offsets(packet);

    if (packet->size > buf_size)
    {
		ssp_handle_incomplete_packet(packet, *segbuf, buf_size);
		return SSP_INCOMPLETE;
	}

	if (ssp_packet_checksum(packet) == SSP_FAILED)
		return SSP_FAILED;

	return ssp_parse_opt_data(packet, ctx, segbuf, source_data);
}

i32
ssp_parse_buf(ssp_ctx_t* ctx, ssp_segbuf_t* segbuf, void* buf, u32 buf_size, void* source_data)
{
    i32 ret;
    ssp_packet_t packet;

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

	if ((ret = ssp_parse_header(&packet, ctx, &segbuf, buf, buf_size, &source_data)) == SSP_SUCCESS)
	    ret = ssp_parse_payload(ctx, &packet, source_data);

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
	f32 new_interval = rtt_ms + RESEND_SAFETY_MARGIN_MS;

	if (new_interval >= RESEND_SAFETY_MARGIN_MS)
		segbuf->retry_interval_ms = new_interval;
}
