#include "ssp_ring.h"
#include <stdlib.h>

void 
ssp_ring_init(ssp_ring_t* ring, u32 element_size, u32 max_elements)
{
	ring->size = element_size * max_elements;
	ring->buf = calloc(1, ring->size);
	ring->end = ring->buf + ring->size - 1;
	ring->read = ring->buf;
	ring->write = ring->buf;
	ring->ele_size = element_size;
	ring->max_elements = max_elements;
	ring->count = 0;
}

void 
ssp_ring_write_ptr(ssp_ring_t* ring, void* ptr)
{
	*(void**)ring->write = ptr;
	ring->write += sizeof(void*);

	if (ring->write > ring->end)
		ring->write = ring->buf;

	ring->count++;
	if ((u32)ring->count > ring->max_elements)
		ring->count = ring->max_elements;
}

void 
ssp_ring_write_u16(ssp_ring_t* ring, u16 val)
{
	*(u16*)ring->write = val;

	ring->write += sizeof(u16);
	if (ring->write > ring->end)
		ring->write = ring->buf;

	ring->count++;
	if ((u32)ring->count > ring->max_elements)
		ring->count = ring->max_elements;
}

bool 
ssp_ring_read_u16(ssp_ring_t* ring, u16* val)
{
	if (ring->count <= 0)
		return false;

	*val = *(u16*)ring->read;
	ring->read += sizeof(u16);

	if (ring->read > ring->end)
		ring->read = ring->buf;

	ring->count--;

	return true;
}

bool 
ssp_ring_read_ptr(ssp_ring_t* ring, void** ptr)
{
	if (ring->count <= 0)
		return false;

	*ptr = *(void**)ring->read;
	ring->read += sizeof(void*);

	if (ring->read > ring->end)
		ring->read = ring->buf;

	ring->count--;

	return true;
}

void 
ssp_ring_free(ssp_ring_t* ring)
{
	free(ring->buf);
}
