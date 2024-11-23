#ifndef _SSP_SLIDING_WINDOW_H_
#define _SSP_SLIDING_WINDOW_H_

#include "sspint.h"

typedef struct ssp_packet ssp_packet_t;

#define SSP_WINDOW_SIZE 16
#define SSP_WINDOW_TIMEOUT_MARGIN_MS 50

typedef struct 
{
	ssp_packet_t* window[SSP_WINDOW_SIZE];
	u16		next_seq;
	i32		count;
	f32		timeout_ms;
	i32		read_idx;
} ssp_window_t;

/* Returns true if packet should be processed, or false dont proceess */
void ssp_window_init(ssp_window_t* win);
void ssp_window_add_packet(ssp_window_t* win, ssp_packet_t* packet);
ssp_packet_t* ssp_window_get_packet(ssp_window_t* win, f64 current_time);
void ssp_slide_window(ssp_window_t* win);
void ssp_window_print(const ssp_window_t* win);

#endif // _SSP_SLIDING_WINDOW_H_
