#ifndef _UFT_SERVER_H_
#define _UFT_SERVER_H_

#include "udp_common.h"
#include "mmframes.h"
#include "nano_timer.h"

typedef struct 
{
	u32 session_id;
	uft_addr_t addr;
	ssp_io_t io;
	bool connected;

	i32 file_fd;
} client_t;

typedef struct 
{
	i32 sockfd;
	struct sockaddr_in addr;
	socklen_t addr_len;
	ght_t clients;
	ssp_io_ctx_t ssp_ctx;
	mmframes_t mmf;
} uft_server_t;

#endif // _UFT_SERVER_H_
