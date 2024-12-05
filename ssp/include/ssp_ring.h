#ifndef _SSP_RING_H_
#define _SSP_RING_H_

/**
 *	SSP Ring - Generic Ring/Circular Buffer
 */

#include "sspint.h"

typedef struct 
{
	void* buf;
	void* read;
	void* write;
	void* end;
	u32   size;
	u32	  ele_size;
	u32	  count;
	u32	  max_count;
} ssp_ring_t;

void ssp_ring_init(ssp_ring_t* ring, u32 ele_size, u32 max_count);
void* ssp_ring_read(ssp_ring_t* ring);
const void* ssp_ring_peak(const ssp_ring_t* ring);
void* ssp_ring_emplace_write(ssp_ring_t* ring);
const void* ssp_ring_inter(const ssp_ring_t* ring, const void** read, u32* count);
void ssp_ring_reset(ssp_ring_t* ring);
void ssp_ring_deinit(ssp_ring_t* ring);

#endif // _SSP_RING_H_
