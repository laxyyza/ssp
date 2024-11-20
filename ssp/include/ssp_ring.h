#ifndef _SSP_RING_H_
#define _SSP_RING_H_

#include "sspint.h"

typedef struct 
{
	u16* buf;
	u16* end;
	u16* read;
	u16* write;
	i32  count;
	u32  size;
} ssp_ringi16_t;

void ssp_ringi16_init(ssp_ringi16_t* ring, u32 size);
void ssp_ringi16_write(ssp_ringi16_t* ring, u16 val);
bool ssp_ringi16_read(ssp_ringi16_t* ring, u16* val);
void ssp_ringi16_free(ssp_ringi16_t* ring);

#endif // _SSP_RING_H_
