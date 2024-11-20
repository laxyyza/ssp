ssp_proto = Proto("my_ssp", "Simple Segmented Protocol")

local SSPFlags = {
    FOOTER = 0x80,               -- 10000000
    SESSION = 0x40,              -- 01000000
    SEQUENCE_COUNT = 0x20,       -- 00100000
    ZSTD_COMPRESSION = 0x10,     -- 00010000
    PAYLOAD_16_BIT = 0x08,       -- 00001000
    IMPORTANT = 0x04,			 -- 00000100
    ACK	= 0x02,					 -- 00000010
}

-- Define fields
ssp_proto.fields.magic = ProtoField.uint32("ssp.magic", "Magic", base.HEX)
ssp_proto.fields.flags = ProtoField.uint8("ssp.flags", "Flags", base.HEX)
ssp_proto.fields.segment_count = ProtoField.uint8("ssp.segment_count", "Segment Count", base.DEC)
ssp_proto.fields.payload_size = ProtoField.uint16("ssp.payload_size", "Payload Size", base.DEC)
ssp_proto.fields.session_id = ProtoField.uint32("ssp.session_id", "Session ID", base.HEX)
ssp_proto.fields.sequence_count = ProtoField.uint16("ssp.sequence_count", "Sequence Count", base.DEC)
ssp_proto.fields.ack = ProtoField.uint16("ssp.ack", "ACK", base.DEC)

-- Add individual flag descriptions
ssp_proto.fields.flag_footer = ProtoField.bool("ssp.flags.footer", "Footer Present (F)", 8, nil, SSPFlags.FOOTER)
ssp_proto.fields.flag_session = ProtoField.bool("ssp.flags.session", "Session ID Present (S)", 8, nil, SSPFlags.SESSION)
ssp_proto.fields.flag_sequence = ProtoField.bool("ssp.flags.sequence", "Sequence Count Present (Q)", 8, nil, SSPFlags.SEQUENCE_COUNT)
ssp_proto.fields.flag_compression = ProtoField.bool("ssp.flags.compression", "Zstd Compression (Z)", 8, nil, SSPFlags.ZSTD_COMPRESSION)
ssp_proto.fields.flag_payload = ProtoField.bool("ssp.flags.payload", "16-bit Payload Size (P)", 8, nil, SSPFlags.PAYLOAD_16_BIT)
ssp_proto.fields.flag_important = ProtoField.bool("ssp.flags.important", "Important (I)", 8, nil, SSPFlags.IMPORTANT)
ssp_proto.fields.flag_ack = ProtoField.bool("ssp.flags.ack", "ACK (A)", 8, nil, SSPFlags.ACK)

-- Segment Fields
ssp_proto.fields.segment_type = ProtoField.uint8("ssp.segment.type", "Segment Type", base.HEX)
ssp_proto.fields.segment_size = ProtoField.uint16("ssp.segment.size", "Segment Size", base.DEC)
ssp_proto.fields.segment_data = ProtoField.bytes("ssp.segment.data", "Segment Data")

-- Dissector function
function ssp_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "SSP"
    
    -- Start parsing the header
    local subtree = tree:add(ssp_proto, buffer(), "Simple Segmented Protocol")
    subtree:add_le(ssp_proto.fields.magic, buffer(0, 4))

    -- Parse FLAGS
    local flags = buffer(4, 1):le_uint()
    local flags_tree = subtree:add(ssp_proto.fields.flags, buffer(4, 1))
    -- Add flag breakdown
    flags_tree:add(ssp_proto.fields.flag_footer, buffer(4, 1))
    flags_tree:add(ssp_proto.fields.flag_session, buffer(4, 1))
    flags_tree:add(ssp_proto.fields.flag_sequence, buffer(4, 1))
    flags_tree:add(ssp_proto.fields.flag_compression, buffer(4, 1))
    flags_tree:add(ssp_proto.fields.flag_payload, buffer(4, 1))
    flags_tree:add(ssp_proto.fields.flag_important, buffer(4, 1))
    flags_tree:add(ssp_proto.fields.flag_ack, buffer(4, 1))

    -- Segment Count
    local segment_count = buffer(5, 1):le_uint()
    subtree:add_le(ssp_proto.fields.segment_count, buffer(5, 1))

    -- Determine payload size
    local payload_offset = 6
    local payload_size
	local actual_payload_offset
    if (flags & SSPFlags.PAYLOAD_16_BIT) ~= 0 then
        payload_size = buffer(payload_offset, 2):le_uint()
        subtree:add_le(ssp_proto.fields.payload_size, buffer(payload_offset, 2)):append_text(" bytes (16-bit)")
        payload_offset = payload_offset + 2
    else
        payload_size = buffer(payload_offset, 1):le_uint()
        subtree:add(ssp_proto.fields.payload_size, buffer(payload_offset, 1)):append_text(" bytes (8-bit)")
        payload_offset = payload_offset + 1
    end

	    -- Check if Zstd compression is set
    if (flags & SSPFlags.ZSTD_COMPRESSION) ~= 0 then
        -- If compressed, don't parse the payload, just display it as compressed
        local compressed_tree = subtree:add("Payload (Zstd compressed)", buffer(payload_offset, payload_size))
        return
    end

	actual_payload_offset = payload_offset

    -- Optional session_id (if SSP_SESSION_BIT is set)
    local session_id = nil
    if (flags & SSPFlags.SESSION) ~= 0 then
        session_id = buffer(payload_offset, 4):le_uint()
        subtree:add_le(ssp_proto.fields.session_id, buffer(payload_offset, 4))
        payload_offset = payload_offset + 4
    end

    -- Optional sequence_count (if SSP_SEQUENCE_COUNT_BIT is set)
    local sequence_count = nil
    if (flags & SSPFlags.SEQUENCE_COUNT) ~= 0 then
        sequence_count = buffer(payload_offset, 2):le_uint()
        subtree:add_le(ssp_proto.fields.sequence_count, buffer(payload_offset, 2))
        payload_offset = payload_offset + 2
    end

    local ack = nil
    if (flags & SSPFlags.ACK) ~= 0 then
        ack = buffer(payload_offset, 2):le_uint()
        subtree:add_le(ssp_proto.fields.ack, buffer(payload_offset, 2))
        payload_offset = payload_offset + 2
    end

	local payload_tree = subtree:add("Payload: Segments", buffer(actual_payload_offset, payload_size))

    -- Parse segments
    local remaining_payload_size = payload_size
    for i = 0, segment_count - 1 do
        -- Each segment: type, size, and data
        local segment_offset = payload_offset
        local segment_type_byte = buffer(segment_offset, 1):le_uint()

		local is_16_bit_size = (segment_type_byte & 0x80) ~= 0
		local segment_type = segment_type_byte & 0x7F
		local segment_size_bytes = 1

		local segment_size;
		local segment_size_offset = segment_offset + 1

		if is_16_bit_size then
			segment_size = buffer(segment_size_offset, 2):le_uint()
			segment_size_offset = segment_size_offset + 2
			segment_size_bytes = 2
		else
			segment_size = buffer(segment_size_offset, 1):le_uint()
			segment_size_offset = segment_size_offset + 1
		end

        local segment_tree = payload_tree:add(ssp_proto, buffer(segment_offset, segment_size + 2), "Segment " .. i)
		if is_16_bit_size then
			segment_tree:add(ssp_proto.fields.segment_type, buffer(segment_offset, 1)):append_text(" (16-bit size, Type: " .. segment_type .. ")")
		else
			segment_tree:add(ssp_proto.fields.segment_type, buffer(segment_offset, 1)):append_text(" (Type: " .. segment_type .. ")")
		end

        segment_tree:add(ssp_proto.fields.segment_size, buffer(segment_size_offset - 1, segment_size_bytes)):append_text(" bytes")

        segment_tree:add(ssp_proto.fields.segment_data, buffer(segment_size_offset, segment_size))

        payload_offset = segment_size_offset + segment_size
        remaining_payload_size = remaining_payload_size - (segment_size + 2)
    end
end

-- Register dissector
udp_table = DissectorTable.get("udp.port")
udp_table:add(49421, ssp_proto)

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(49420, ssp_proto)
