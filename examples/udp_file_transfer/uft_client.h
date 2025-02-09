#ifndef _UFT_CLIENT_H_
#define _UFT_CLIENT_H_

#include "udp_common.h"
#include "mmframes.h"

typedef struct 
{
	i32 sockfd;
	struct sockaddr_in server_addr;
	socklen_t addr_len;
	ssp_io_ctx_t ssp_ctx;
	ssp_io_t io;
	mmframes_t mmf;

	const char* ip_address;
	const char* server_path;
	const char* local_path;
	i32 local_fd;
	u64 file_size;
	u64 file_index;
	void* file_data;
	bool upload;

	bool connected;
	bool busy_uploading;
} uft_client_t;

#endif // _UFT_CLIENT_H_
