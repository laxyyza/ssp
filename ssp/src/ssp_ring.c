#include "ssp_ring.h"
#include <stdlib.h>

void 
ssp_ring_init(ssp_ring_t* ring, u32 ele_size, u32 max_count)
{
	ring->size = ele_size * max_count;
	ring->ele_size = ele_size;
	ring->buf = malloc(ring->size);
	ring->read = ring->buf;
	ring->write = ring->buf;
	ring->end = ring->buf + ring->size - 1;
	ring->count = 0;
	ring->max_count = max_count;
}

void* 
ssp_ring_read(ssp_ring_t* ring)
{
	void* ret;
	if (ring->count == 0)
		return NULL;

	ret = ring->read;

	ring->read += ring->ele_size;
	if (ring->read >= ring->end)
		ring->read = ring->buf;

	ring->count--;

	return ret;
}

const void* 
ssp_ring_peak(const ssp_ring_t* ring)
{
	return (ring->count) ? ring->read : NULL;
}

void* 
ssp_ring_emplace_write(ssp_ring_t* ring)
{
	void* ret;

	ret = ring->write;

	ring->write += ring->ele_size;
	if (ring->write >= ring->end)
		ring->write = ring->buf;

	if (ring->count < ring->max_count)
		ring->count++;

	return ret;
}

const void* 
ssp_ring_inter(const ssp_ring_t* ring, const void** read_p, u32* count)
{
	if (ring->count == 0 || *count >= ring->count)
		return NULL;

	const void* ret;
	const void* read = *read_p;

	if (read == NULL)
		read = ring->read;

	ret = read;

	read += ring->ele_size;
	if (read >= ring->end)
		read = ring->buf;
	*read_p = read;
	(*count)++;

	return ret;
}

void 
ssp_ring_reset(ssp_ring_t* ring)
{
	ring->count = 0;
	ring->read = ring->write = ring->buf;
}

void 
ssp_ring_deinit(ssp_ring_t* ring)
{
	free(ring->buf);
}
