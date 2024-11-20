# SSP - Simple Segmented Protocol
SSP is a dynamic, application-level binary protocol designed to work over both TCP and UDP. Its payload is divided into 'segments,' allowing multiple types of data to be transmitted within a single packet. For example, a single game packet could include a player's position, input, events, and more.

This project encompasses the protocol's structure, its implementation, and a C-based network library. The library is designed to buffer multiple data segments before serializing them into a single packet for transmission.

## Protocol Structure
Here's a high-level overview of a packet:
```
[ [ header ] [ payload: {segment0, segment1, ...} ] [ footer (optional) ] ]
```
### Header Details:
```
[32-bit magic] [8-bit flags] [8-bit segment_count] [8-16-bit payload_size]
   [32-bit session_id (opt)] [16-bit sequence_count (opt)]
```
- `magic`: A unique identifier for the packet.
- `segment_count`: The number of segments present in the payload.
- `payload_size`: The size of the payload in bytes.
- `flags`: A set of options for the packet, represented by the following bits:
```
   MSB [7 6 5 4 3 2 1 0] LSB
        F S Q Z P R R R
```
- Flag Details:
    - (F) Footer: Indicates the presence of a 32-bit checksum for the packet.
    - (S) Session ID: Includes a 32-bit session ID (useful for UDP).
    - (Q) Sequence Count: Includes a 16-bit sequence count for tracking packet order.
    - (Z) Zstd Compression: Indicates that the payload is compressed using Zstd.
    - (P) 16-bit Payload Size: Specifies that the payload size uses 16 bits instead of the default 8 bits.
    - (R) Reserved: Bits reserved for future use.
#### Example
A header with the `F`, `S`, and `P` flags set would include a footer checksum, session ID, and a 16-bit payload size field. The structure dynamically adjusts based on the flags, allowing flexible and efficient packet formatting.

### Payload Details:

The payload is divided into _segments_, with each `segment` consisting of a type, size, and data:
```
[ [1-bit 16-bit size][7-bit type][8-16-bit size][data ...] ]
```
- `type` The type of data contained in the segment.
- `size` The size of the data in bytes.
- `data` The actual data being transmitted.

Detailed Payload View
```
[ [32-bit session ID][16-bit sequence count] [8-bit type][8-16-bit size][data ...][8-bit type][8-16-bit size][data ...] ...  ]
```

### Footer Details

The footer contains the checksum of the packet. It is optional and is included if the `FOOTER_BIT` flag is set.

**Footer View:**
```
[32-bit checksum]
```
## Limitations
- Maximum payload size of 65,535 bytes (16-bit limit).
- Supports up to 127 unique segment data types (7-bit limit).
- Endianness-dependent.
