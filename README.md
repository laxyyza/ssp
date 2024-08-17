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
[ [32-bit magic][32-bit size][8-bit flags][8-bit segment count] ]
```
- `magic`: A unique identifier for the packet.
- `size`: The size of the payload in bytes.
- `flags`: Options for the packet, represented by flag bits:
```
[0 1 2 3 4 5 6 7]
 F R R R R R R R

    F - Footer Flag (FOOTER_BIT)
    R - Reserved
```
- `segment count`: The number of segments present in the payload.
### Payload Details:

The payload is divided into _segments_, with each `segment` consisting of a type, size, and data:
```
[ [16-bit type][32-bit size][data ...] ]
```
- `type` The type of data contained in the segment.
- `size` The size of the data in bytes.
- `data` The actual data being transmitted.

Detailed Payload View
```
[ [16-bit type][32-bit size][data ...][16-bit type][32-bit size][data ...] ...  ]
```

### Footer Details

The footer contains the checksum of the packet. It is optional and is included if the `FOOTER_BIT` flag is set.

**Footer View:**
```
[32-bit checksum]
```
## Potential Future Enhancements
- **Endianness:** Currently, the protocol assumes little-endian format. Future improvements could include support for different endianness to ensure compatibility across various systems.
- **Dynamic Header:** Consider implementing a dynamic-sized header. For example, if the payload size is less than 256 bytes, use an 8-bit size field; for payloads larger than 255 bytes but less than 65,535 bytes, use a 16-bit size field; and for even larger payloads, use a 32-bit size field, etc.
- **Additional Features:** As the protocol is still in its early stages and has not yet been deployed in a real application, there may be additional features or improvements that arise based on practical usage and requirements.
