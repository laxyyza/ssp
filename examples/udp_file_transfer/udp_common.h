#ifndef _UDP_COMMON_H_
#define _UDP_COMMON_H_

#define _GNU_SOURCE
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <poll.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

#include <ssp.h>

#define PORT 49421
#define UFT_SSP_MAGIC 0x8810a760
#define UFT_SSP_FLAGS (SSP_IMPORTANT_BIT | SSP_SESSION_BIT)

#define MAX_FILE_NAME 256
#define MAX_FILE_PATH 1024
#define ERROR_MSG_LEN 512
#define FILE_CHUNK 1024

enum segment_types 
{
	UFT_CONNECT,
	UFT_UPLOAD,
	UFT_DOWNLOAD,
	UFT_OK,
	UFT_ERROR,
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
	u64	 file_size;
	u16  path_len;
	mode_t mode;
	char path[];
} uft_upload_t;

typedef struct 
{
	u32 session_id;
} uft_session_t;

typedef struct 
{
	i32 code;
	char msg[ERROR_MSG_LEN];
} uft_error_t;

i32 file_exists(const char* path, bool create, mode_t mode);
u64 file_size(i32 fd, mode_t* mode);

#endif // _UDP_COMMON_H_

