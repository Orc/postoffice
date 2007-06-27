#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>


char *
mapfd(int fd, size_t *size)
{
    struct stat info;
    char *map;

    if (fstat(fd, &info) == -1)
	return 0;

    if ( (map = mmap(0,info.st_size,PROT_READ,MAP_SHARED,fd,0L)) == (void*)-1)
	return 0;

    *size = info.st_size;
    return map;
}
