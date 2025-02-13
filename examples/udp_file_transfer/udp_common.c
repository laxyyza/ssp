#include "udp_common.h"

i32
file_exists(const char* path, bool create, mode_t mode)
{
	i32 fd;

	if (create)
		fd = open(path, O_RDWR | O_CREAT, mode); 
	else
		fd = open(path, O_RDONLY); 

	return fd;
}

u64 
file_size(i32 fd, mode_t* mode)
{
	struct stat stat;
	if (fstat(fd, &stat) == -1)
		perror("fstat");
	if (mode)
		*mode = stat.st_mode;
	return stat.st_size;
}

