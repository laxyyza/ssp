# SSP - Simple Segmented Protocol 

SSP is a dynamic, application-level binary protocol designed to work over both TCP and UDP. Its payload is divided into 'segments,' allowing multiple types of data to be transmitted within a single packet. For example, a single game packet could include a player's position, input, events, and more.

This project encompasses the protocol's structure, its implementation, and a C-based network library. The library is designed to buffer multiple data segments before serializing them into a single packet for transmission.

## Protocol Structure
The packet consists of three main components: header, payload (which contains segments), and an optional footer:
```
[ [ header ] [ payload: {segment0, segment1, ...} ] [ footer (optional) ] ]
```
![img](https://github.com/user-attachments/assets/78989527-9f40-4c35-bf58-685400bd715d)
### Header Details:
```
[ 32-bit magic | 8-bit flags | 8-bit segment_count | 8-16-bit payload_size |
  32-bit session_id (opt) | 16-bit sequence_count (opt) | 32-bit ACK-range (opt) ]
```
7-18 bytes. 
- `magic`: A unique identifier for the packet.
- `segment_count`: The number of segments present in the payload.
- `payload_size`: The size of the payload in bytes.
- `flags`: A set of options for the packet, represented by the following bits:
```
   MSB [7 6 5 4 3 2 1 0] LSB
        F S I Z P A R R
```
- **Flag Details:**
    - **(F) Footer:** Indicates the presence of a 32-bit checksum for the packet.
    - **(S) Session ID:** Includes a 32-bit session ID (useful for UDP).
        - **NOTE:** SSP does not generate the session ID; it is the responsibility of the application using SSP to provide one.
    - **(I) Important:** Marks the packet as "important," enhancing its reliability for delivery and ensuring in-order processing. Includes a 16-bit sequence number. The receiver MUST acknowledge the packet by sending an ACK with its sequence number. However, delivery is not guaranteed.
    - **(Z) Zstd Compression:** Indicates that the payload is compressed using Zstandard.
    - **(P) 16-bit Payload Size:** Specifies that the payload size uses 16 bits instead of the default 8 bits.
    - **(A) ACK:** Acknowledgment packet containing the sequence count.
    - **(R) Reserved:** Bits reserved for future use.
#### Example
A header with the `F`, `S`, and `P` flags set would include a footer checksum, session ID, and a 16-bit payload size field. The structure dynamically adjusts based on the flags, allowing flexible and efficient packet formatting.

### Payload Details:
The payload is divided into multiple **segments**, each consisting of a type, size, and data:
```
[ 1-bit flag | 7-bit type | 8-16-bit size | data ... ]
```
- The **1-bit flag** indicates whether the segment size is 16 bits:
    - If the flag is set, the size field is 16 bits; otherwise, it is 8 bits.
- **Type (7 bits):** Specifies the type of data in the segment.
    - **NOTE:** SSP does not define segment types; these are determined by the application(s) using SSP. For example, types might include `PLAYER_POSITION = 1`, `GAME_EVENT = 2`, etc.
- **Size (8 or 16 bits):** Represents the size of the data in bytes.
- **Data:** The actual data being transmitted in the segment.

#### Example Payload Structure:
```
[ 1-bit flag | 7-bit type | 8-16-bit size | data ... ][ 1-bit flag | 7-bit type | 8-16-bit size | data ... ] ...
```

### Footer Details

The footer contains a checksum of the packet for integrity verification. It is optional and is included only if the `SSP_FOOTER_BIT (F)` flag is set.

**Footer View:**
```
[32-bit checksum]
```
**NOTE:** The inclusion of a footer checksum may seem redundant since both TCP and UDP already provide their own checksums. However, this checksum allows the application to verify the integrity of the full SSP packet, independent of the underlying transport layer.
## Limitations
- Maximum payload size of 65,535 bytes (16-bit limit).
- Maximum of 255 segments in the payload (8-bit limit).
- Supports up to 127 unique segment data types (7-bit limit).
- **No endianness conversion support:** The protocol implementation assumes that all devices using SSP share the same endianness.

## Current Status
- This project is still in its early stages and has only been used in one project so far. The protocol is evolving based on its use and future needs.
- The protocol implementation is complete, though edge case testing has not yet been performed.
- Networking functionality is still under development:
    - Basic support for TCP sockets is implemented.
    - No support for UDP sockets has been implemented yet.
