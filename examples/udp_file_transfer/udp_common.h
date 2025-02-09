#ifndef _UDP_COMMON_H_
#define _UDP_COMMON_H_

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <poll.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <ssp.h>

#define PORT 49421
#define UFT_SSP_MAGIC 0x8810a760
#define UFT_SSP_FLAGS (SSP_IMPORTANT_BIT | SSP_SESSION_BIT)

#define MAX_FILE_NAME 256
#define MAX_FILE_PATH 1024
#define FILE_CHUNK 1024

enum segment_types 
{
	UFT_CONNECT,
	UFT_SRC_FILE,
	UFT_DST_FILE,
	UFT_SESSION,
	UFT_FILE_DATA
};

#define UFT_SRC_CLIENT 1
#define UFT_SRC_SERVER 2

typedef struct 
{
	char ip[INET_ADDRSTRLEN];
	u16 port;
	struct sockaddr_in in;
	socklen_t in_len;
} uft_addr_t;

typedef struct 
{
	u8		src; // src from client or server?
	u64		filesize;
	char	path[];
} uft_src_file_t;

typedef struct 
{
	char path[MAX_FILE_PATH];
} uft_dst_file_t;

typedef struct 
{
	u32 session_id;
} uft_session_t;

#endif // _UDP_COMMON_H_

