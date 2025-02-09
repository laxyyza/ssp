#include "udp_common.h"

i32
file_exists(const char* path, bool create)
{
	i32 fd;

	if (create)
		fd = open(path, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH); 
	else
		fd = open(path, O_RDONLY); 

	return fd;
}

u64 
file_size(i32 fd)
{
	struct stat stat;
	if (fstat(fd, &stat) == -1)
		perror("fstat");
	return stat.st_size;
}

