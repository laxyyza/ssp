#include "ssp.h"
#include <string.h>
#include <stdio.h>
#include <zstd.h>

void 
ssp_state_init(ssp_state_t* state)
{
    ght_init(&state->segment_map, 10, NULL);
}

void 
ssp_state_destroy(ssp_state_t* state)
{
	ght_destroy(&state->segment_map);
}

void 
ssp_segmap(ssp_state_t* state, u16 segtype, ssp_segmap_callback_t callback)
{
    ght_insert(&state->segment_map, segtype, callback);
}

ssp_segmap_callback_t 
ssp_get_segmap(ssp_state_t* state, u16 segtype)
{
    return ght_get(&state->segment_map, segtype);
}

u64 
ssp_calc_psize(u32 payload_size, u8 flags)
{
	u64 packet_size = sizeof(ssp_header_t) + payload_size;

	if (flags & SSP_FOOTER_BIT)
		packet_size += sizeof(ssp_footer_t);
	if (flags & SSP_SESSION_BIT)
		packet_size += sizeof(u32);
	if (flags & SSP_SEQUENCE_COUNT_BIT)
		packet_size += sizeof(u16);

	return packet_size;
}

u64 
ssp_packet_size(const ssp_packet_t* packet)
{
    return ssp_calc_psize(packet->header.size,
                          packet->header.flags);
}

u64 
ssp_checksum_size(const ssp_packet_t* packet)
{
    return ssp_calc_psize(packet->header.size, 0);
}

u64 
ssp_seg_size(const ssp_segment_t* seg)
{
    return sizeof(ssp_segment_t) + seg->size;
}

ssp_packet_t*
ssp_new_packet(u32 size, u8 flags)
{
    ssp_packet_t* packet;

    packet = calloc(1, ssp_calc_psize(size, flags));
    packet->header.magic = SSP_MAGIC;
    packet->header.flags = flags;
    packet->header.size = size;

    return packet;
}

ssp_footer_t*  
ssp_get_footer(const ssp_packet_t* packet)
{
    uint8_t* u8packet = (u8*)packet;
    ssp_footer_t* footer;
    if (packet == NULL || packet->header.size == 0 || (packet->header.flags & SSP_FOOTER_BIT) == 0)
        return NULL;
    footer = (ssp_footer_t*)(u8packet + (sizeof(ssp_packet_t) + packet->header.size));
    return footer;
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
ssp_get_segbuf_total_size(const ssp_segbuff_t* segbuf)
{
    u32 total = 0;

	if (segbuf->flags & SSP_SESSION_BIT)
		total += sizeof(u32);
	if (segbuf->flags & SSP_SEQUENCE_COUNT_BIT)
		total += sizeof(u16);

    for (u32 i = 0; i < segbuf->count; i++)
        total += segbuf->segments[i].size;

    return total;
}

static void
ssp_serialize(ssp_packet_t* packet, ssp_segbuff_t* segbuf)
{
    u32 offset = 0;
	void* payload;
    packet->header.segments = segbuf->count;

	if (packet->header.flags & SSP_ZSTD_COMPRESSION_BIT || 
		(segbuf->compression.auto_do && packet->header.size > segbuf->compression.threshold))
	{
		payload = malloc(packet->header.size);
		packet->header.flags |= SSP_ZSTD_COMPRESSION_BIT;
	}
	else
		payload = packet->payload;

	if (segbuf->flags & SSP_SESSION_BIT)
	{
		memcpy(payload + offset, &segbuf->session_id, sizeof(u32));
		offset += sizeof(u32);
	}
	if (segbuf->flags & SSP_SEQUENCE_COUNT_BIT)
	{
		segbuf->seqc_sent++;
		memcpy(payload + offset, &segbuf->seqc_sent, sizeof(u16));
		offset += sizeof(u16);
	}

    for (u32 i = 0; i < segbuf->count; i++)
    {
        const ssp_seglisten_t* seglisten = segbuf->segments + i;
        ssp_segment_t* segment = (ssp_segment_t*)(payload + offset);

        segment->type = seglisten->type;
        segment->size = seglisten->size;
        memcpy(segment->data, seglisten->data, segment->size);

        offset += segment->size + sizeof(ssp_segment_t);
    }

	if (packet->header.flags & SSP_ZSTD_COMPRESSION_BIT)
	{
		u64 compressed_size = ZSTD_compress(packet->payload, ZSTD_compressBound(packet->header.size), payload, packet->header.size, segbuf->compression.level);
		if (ZSTD_isError(compressed_size))
		{
			fprintf(stderr, "ZSTD_compress FAILED: %s\n", ZSTD_getErrorName(compressed_size));
			packet->header.flags ^= SSP_ZSTD_COMPRESSION_BIT;
			memcpy(packet->payload, payload, packet->header.size);
		}
		else
		{
			printf("SSP Packet payload compressed from %u -> %zu bytes.\n", 
				packet->header.size, compressed_size);
			packet->header.size = compressed_size;
		}
	}
}

ssp_packet_t* 
ssp_serialize_packet(ssp_segbuff_t* segbuf)
{
    ssp_packet_t* packet;
    ssp_footer_t* footer;
    u32 payload_size;

    if (segbuf->count == 0)
        return NULL;

    payload_size = ssp_get_segbuf_total_size(segbuf) + 
                    (sizeof(ssp_segment_t) * segbuf->count);
    packet = ssp_new_packet(payload_size, segbuf->flags);

    ssp_serialize(packet, segbuf);

    if ((footer = ssp_get_footer(packet)))
        footer->checksum = ssp_checksum32(packet, ssp_calc_psize(packet->header.size, 0));

    ssp_segbuff_clear(segbuf);

    return packet;
}

ssp_packet_t* 
ssp_insta_packet(ssp_segbuff_t* source_segbuf, u16 type, const void* buf, u64 size)
{
	ssp_packet_t* ret;
	ssp_seglisten_t segment = {
		.data = buf,
		.size = size,
		.type = type
	};
	ssp_segbuff_t segbuf = {
		.count = 1,
		.size = 1,
		.min_size = 1,
		.session_id = source_segbuf->session_id,
		.flags = source_segbuf->flags,
		.seqc_sent = source_segbuf->seqc_sent,
		.segments = &segment
	};

	ret = ssp_serialize_packet(&segbuf);
	source_segbuf->seqc_sent = segbuf.seqc_sent;

	return ret;
}

void 
ssp_segbuff_init(ssp_segbuff_t* segbuf, u32 init_size, u8 flags)
{
    segbuf->segments = calloc(init_size, sizeof(ssp_seglisten_t));
    segbuf->size = init_size;
    segbuf->count = 0;
    segbuf->min_size = init_size;
    segbuf->inc_size = init_size;
	segbuf->flags = flags;
}

void 
ssp_segbuff_resize(ssp_segbuff_t* segbuf, u32 new_size)
{
    if (new_size < segbuf->min_size)
        new_size = segbuf->min_size;
    if (new_size == segbuf->size)
        return;

    segbuf->segments = realloc(segbuf->segments, new_size * sizeof(ssp_seglisten_t));
    segbuf->size = new_size;
}

void    
ssp_segbuff_add(ssp_segbuff_t* segbuf, u16 type, u32 size, const void* data)
{
    for (u32 i = 0; i < segbuf->count; i++)
	{
        const ssp_seglisten_t* seglisten = segbuf->segments + i;
		if (seglisten->data == data && seglisten->size == size)
			return; // Dont duplicate data.
	}

    ssp_seglisten_t* seglisten = segbuf->segments + segbuf->count;
    seglisten->type = type;
    seglisten->size = size;
    seglisten->data = data;
    segbuf->count++;

    if (segbuf->count >= segbuf->size)
        ssp_segbuff_resize(segbuf, segbuf->size + segbuf->inc_size);
}

void 
ssp_segbuff_clear(ssp_segbuff_t* segbuf)
{
    if (segbuf == NULL)
        return;

    segbuf->count = 0;
    ssp_segbuff_resize(segbuf, segbuf->min_size);
}

void 
ssp_segbuff_destroy(ssp_segbuff_t* segbuf)
{
	free(segbuf->segments);
}

static i32
ssp_parse_payload(ssp_state_t* state, ssp_segbuff_t* segbuf, 
				  const ssp_packet_t* packet, void* source_data)
{
    i32 ret = SSP_SUCCESS;
    u32 offset = 0;
	void* payload;
    ssp_segment_t* segment;
    ssp_segmap_callback_t segmap_callback;
    bool segmap_called = false;

	if (packet->header.flags & SSP_ZSTD_COMPRESSION_BIT)
	{
		u32 og_size = ZSTD_getFrameContentSize(packet->payload, packet->header.size);
		payload = malloc(og_size);
		u64 decompress_size = ZSTD_decompress(payload, og_size, packet->payload, packet->header.size);
		if (ZSTD_isError(decompress_size))
		{
			fprintf(stderr, "ZSTD_decompress FAILED: %s\n", ZSTD_getErrorName(decompress_size));
			free(payload);
			return SSP_FAILED;
		}
		printf("SSP Payload decompressed from: %u -> %zu (og: %u)\n", packet->header.size, decompress_size, og_size);
	}
	else
		payload = (void*)packet->payload;

	if (packet->header.flags & SSP_SESSION_BIT)
	{
		const u32 session_id = *(u32*)(payload + offset);

		// Verify session ID...
		if (state->verify_session)
		{
			void* new_source = NULL;
			if (state->verify_session(session_id, state->user_data, source_data, &new_source, &segbuf) == false)
				return SSP_FAILED;
			if (new_source)
				source_data = new_source;
		}

		offset += sizeof(u32);
	}
	if (packet->header.flags & SSP_SEQUENCE_COUNT_BIT)
	{
		if (segbuf)
		{
			const u16 seqc_recv = *(u16*)(payload + offset);

			if (segbuf->seqc_recv + 1 != seqc_recv)
			{
				printf("Packet seqc_recv: %u + 1 != %u. Packet loss?\n",
						segbuf->seqc_recv, seqc_recv);
			}

			segbuf->seqc_recv = seqc_recv;
		}

		offset += sizeof(u16);
	}

    for (u32 i = 0; i < packet->header.segments; i++)
    {
        segment = (ssp_segment_t*)(payload + offset);

        if ((segmap_callback = ssp_get_segmap(state, segment->type)))
        {
            segmap_callback(segment, state->user_data, source_data);
            segmap_called = true;
        }
        else
            ret = SSP_SEGMAP_NO_ASSIGN;

        offset += segment->size + sizeof(ssp_segment_t);
    }
	if (packet->header.flags & SSP_ZSTD_COMPRESSION_BIT)
		free(payload);
    return (segmap_called) ? ret : SSP_NOT_USED;
}

i32
ssp_parse_buf(ssp_state_t* state, ssp_segbuff_t* segbuf, const void* buf, u64 buf_size, void* source_data)
{
    i32 ret;
    const ssp_packet_t* packet = buf;
    ssp_footer_t* footer = NULL;
    u32 our_checksum;
    u64 packet_size;
    bool another_packet = false;

	if (segbuf && segbuf->recv_incomplete.packet)
	{
		memcpy((u8*)segbuf->recv_incomplete.packet + segbuf->recv_incomplete.current_size, buf, buf_size);
		segbuf->recv_incomplete.current_size += buf_size;

		if (segbuf->recv_incomplete.current_size < segbuf->recv_incomplete.packet_size)
			return SSP_INCOMPLETE;

		packet = segbuf->recv_incomplete.packet;
		buf_size = segbuf->recv_incomplete.current_size;
		segbuf->recv_incomplete.current_size = segbuf->recv_incomplete.packet_size = 0;
	}

    if (packet->header.magic != SSP_MAGIC)
        return SSP_FAILED;

    packet_size = ssp_packet_size(packet);
    if (packet_size > buf_size)
    {
		if (segbuf)
		{
			segbuf->recv_incomplete.packet = calloc(1, packet_size);
			memcpy(segbuf->recv_incomplete.packet, buf, buf_size);
			segbuf->recv_incomplete.packet_size = packet_size;
			segbuf->recv_incomplete.current_size = buf_size;
		}
		else
			fprintf(stderr, "WARNING: ssp_parse_buf: segbuf is NULL and packet is incomplete!\n");
		return SSP_INCOMPLETE;
	}
    else if (packet_size < buf_size)
        another_packet = true;

    if ((footer = ssp_get_footer(packet)))
    {
        our_checksum = ssp_checksum32(packet, ssp_checksum_size(packet));
        if (our_checksum != footer->checksum)
		{
			printf("Corrupt packet. Checksum mismatch: 0x%X != 0x%X\n",
					our_checksum, footer->checksum);
            return SSP_FAILED;
		}
    }

    ret = ssp_parse_payload(state, segbuf, packet, source_data);

	if (segbuf && segbuf->recv_incomplete.packet && segbuf->recv_incomplete.packet_size == 0)
	{
		free(segbuf->recv_incomplete.packet);
		segbuf->recv_incomplete.packet = NULL;
	}

    return (another_packet) ? SSP_MORE : ret;
}
