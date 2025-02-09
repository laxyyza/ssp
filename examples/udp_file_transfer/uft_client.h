#ifndef _UFT_CLIENT_H_
#define _UFT_CLIENT_H_

#include "udp_common.h"

typedef struct 
{
	i32 sockfd;
	struct sockaddr_in server_addr;
	socklen_t addr_len;
	ssp_io_ctx_t ssp_ctx;
	ssp_io_t io;
	bool connected;
} uft_client_t;

#endif // _UFT_CLIENT_H_
