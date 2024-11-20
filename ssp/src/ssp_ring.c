#include "ssp_ring.h"
#include <stdlib.h>

void 
ssp_ringi16_init(ssp_ringi16_t* ring, u32 size)
{
	ring->buf = calloc(size, sizeof(u16));
	ring->end = ring->buf + size - 1;
	ring->read = ring->buf;
	ring->write = ring->buf;
	ring->size = size;
	ring->count = 0;
}

void 
ssp_ringi16_write(ssp_ringi16_t* ring, u16 val)
{
	*ring->write = val;

	ring->write++;
	if (ring->write > ring->end)
		ring->write = ring->buf;

	ring->count++;
	if ((u32)ring->count > ring->size)
		ring->count = ring->size;
}

bool 
ssp_ringi16_read(ssp_ringi16_t* ring, u16* val)
{
	if (ring->count <= 0)
		return false;

	*val = *ring->read;
	ring->read++;

	if (ring->read > ring->end)
		ring->read = ring->buf;

	ring->count--;

	return true;
}

void 
ssp_ringi16_free(ssp_ringi16_t* ring)
{
	free(ring->buf);
}
