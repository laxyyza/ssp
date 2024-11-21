#ifndef _SSP_RING_H_
#define _SSP_RING_H_

#include "sspint.h"

typedef struct 
{
	u8* buf;	// Begin buffer
	u8* end;	// End buffer
	u8* read;	// Read head
	u8* write;	// Write head

	i32  count;
	u32  ele_size; // Element Size
	u32  max_elements;
	u32  size;
} ssp_ring_t;

void ssp_ring_init(ssp_ring_t* ring, u32 element_size, u32 max_elements);
void ssp_ring_write_ptr(ssp_ring_t* ring, void* ptr);
void ssp_ring_write_u16(ssp_ring_t* ring, u16 val);
bool ssp_ring_read_u16(ssp_ring_t* ring, u16* val);
bool ssp_ring_read_ptr(ssp_ring_t* ring, void** ptr);
void ssp_ring_free(ssp_ring_t* ring);

#endif // _SSP_RING_H_
