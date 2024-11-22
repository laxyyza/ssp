#include "ssp_window.h"
#include "ssp.h"
#include <stdio.h>
#include <string.h>

void 
ssp_window_init(ssp_window_t* win)
{
	win->timeout_ms = SSP_WINDOW_TIMEOUT_MARGIN_MS;
	win->next_seq = 1; }

void
ssp_window_add_packet(ssp_window_t* win, ssp_packet_t* packet)
{

	u16 seq = *packet->opt_data.seq;

	u32 index = (seq - win->next_seq);
	win->window[index] = packet;
	win->count++;
}

ssp_packet_t*
ssp_window_get_packet(ssp_window_t* win, f64 current_time)
{
	ssp_packet_t* ret;
	u32 idx = 0;

again:
	if (idx >= SSP_WINDOW_SIZE)
		idx = 0;

	ret = win->window[idx];
	if (ret)
	{
		win->window[idx] = NULL;
		win->next_seq = *ret->opt_data.seq + 1;
		win->count--;
	}
	else if (win->count)
	{
		i32 count = 0;
		for (u32 i = 0; i < SSP_WINDOW_SIZE; i++)
		{
			const ssp_packet_t* p = win->window[i];
			if (p)
			{
				f64 elapsed_time = (current_time - p->timestamp) * 1000.0;
				if (elapsed_time >= win->timeout_ms)
				{
					idx = i;
					goto again;
				}
				count++;
				if (count >= win->count)
					break;
			}
		}
	}

	return ret;
}
