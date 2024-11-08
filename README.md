# SSP - Simple Segmented Protocol

SSP is an application-level, binary-based protocol with segmented payload and flexible design, compatible with both TCP and UDP.

Primarily designed for transmitting various types of data within a single packet. For example, a single game packet can include multiple actions such as player movements, actions performed, and other events.

This project includes both the protocol specification and its implementation as a C library.

## Protocol Structure
Here's a high-level overview of a packet:
```
[ [ header ] [ payload: {segment0, segment1, ...} ] [ footer (optional) ] ]
```
### Header Details:
```
[ [32-bit magic][8-bit flags][8-bit segments][8-16-bit payload size] ]
```
- `magic`: A unique identifier for the packet.
- `size`: The size of the payload in bytes.
- `flags`: Options for the packet, represented by flag bits:
```
[0 1 2 3 4 5 6 7]
 F S Q Z R R R R

  0: F - Footer Flag (SSP_FOOTER_BIT)
  1: S - Session id  (SSP_SESSION_BIT)
  2: Q - seQuence count (SSP_SEQUENCE_COUNT_BIT)
  3: Z - Zstd payload compression. (SSP_ZSTD_COMPRESSION_BIT)
4-7: R - Reserved

```
- `segments`: The number of segments present in the payload.
### Payload Details:

The payload is divided into _segments_ (after optional session id and sequence count), with each `segment` consisting of a type, size, and data:
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
