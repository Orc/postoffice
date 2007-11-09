/*
 * getloadavg() for systems that don't have that library call.
 */
#include "config.h"

#if !defined(HAVE_GETLOADAVG)

#if __linux__

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

int
getloadavg(double *la, int size)
{
    char bfr[256];
    int fd, bufsiz, ret=-1, i;
    float vla[3];

    if ( (fd = open("/proc/loadavg", O_RDONLY)) != -1) {

	if ( (bufsiz = read(fd, bfr, sizeof bfr)) > 0) {
	    bfr[bufsiz] = 0;
	    ret = sscanf(bfr, "%f %f %f ", &vla[0], &vla[1], &vla[2]);

	    if (size < ret) ret = size;

	    for (i=0; i < ret; i++)
		la[i] = vla[i];
	}
	close(fd);
    }
    return ret;
}
#endif

#endif/*HAVE_GETLOADAVG*/
