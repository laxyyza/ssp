#include "ssp_window.h"
#include "ssp.h"
#include <stdio.h>
#include <string.h>

void
ssp_window_print(const ssp_window_t* win)
{
	printf("Window, read: %d, next_seq: %u, count: %u, timeout: %f\n", win->read_idx, win->next_seq, win->count, win->timeout_ms);

	for (u32 i = 0; i < SSP_WINDOW_SIZE; i++)
	{
		const ssp_packet_t* p = win->window[i];
		printf("%u: ", i);
		if (p)
		{
			if (*p->opt_data.seq == win->next_seq)
				printf("> ");
			printf("\tsn: %u (%f)\n", *p->opt_data.seq, p->timestamp);
		}
		else
			printf("\tNil\n");
	}
}

void 
ssp_window_init(ssp_window_t* win)
{
	win->timeout_ms = SSP_WINDOW_TIMEOUT_MARGIN_MS;
	win->next_seq = 1; }

void
ssp_window_add_packet(ssp_window_t* win, ssp_packet_t* packet)
{
	u16 seq = *packet->opt_data.seq;

	u32 index = ((seq - win->next_seq) + win->read_idx) % SSP_WINDOW_SIZE;

	if (win->window[index] == NULL)
	{
		win->window[index] = packet;
		win->count++;
	}
}

ssp_packet_t*
ssp_window_get_packet(ssp_window_t* win, f64 current_time)
{
	ssp_packet_t* ret;
again:
	if (win->read_idx >= SSP_WINDOW_SIZE)
		win->read_idx = 0;

	ret = win->window[win->read_idx];
	if (ret)
	{
		win->window[win->read_idx] = NULL;
		if (win->next_seq < *ret->opt_data.seq)
			printf("next_seq:%u < seq:%u\n", win->next_seq, *ret->opt_data.seq);
		win->next_seq = *ret->opt_data.seq + 1;
		win->count--;
		win->read_idx++;
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
					win->read_idx = i;
					goto again;
				}
				count++;
				if (count >= win->count)
					break;
			}
		}
	}
	else
		win->read_idx = 0;

	return ret;
}

void 
ssp_slide_window(ssp_window_t* win, u16 new_seq)
{
	/* Discard all packets in window */
	for (u32 i = 0; i < SSP_WINDOW_SIZE; i++)
	{
		ssp_packet_t* p = win->window[i];
		ssp_packet_free(p);
		win->window[i] = NULL;
	}
	win->next_seq = new_seq;
	win->count = 0;
	win->read_idx = 0;
}
