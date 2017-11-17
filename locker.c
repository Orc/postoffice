/*
 * file locking -- abstracted out because some systems (Minix 3 in
 *                 particular) don't implement flock correctly and
 *                 need the older and klunkier fcntl interface.
 */
#include "config.h"

#include <stdio.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

int
locker(int fd, int mode)
{
#if HAS_FCNTL_LOCK
    struct flock lck;
    register int rc;

    switch ( mode & ~LOCK_NB ) {
    case LOCK_EX: lck.l_type = F_WRLCK; break;
    case LOCK_SH: lck.l_type = F_RDLCK; break;
    case LOCK_UN: lck.l_type = F_UNLCK; break;
    default: errno = EINVAL; return -1;
    }
    lck.l_whence = SEEK_SET;
    lck.l_start = lck.l_len = 0;
    lck.l_pid = getpid();
    
    if ( (rc = fcntl(fd, mode & LOCK_NB ? F_SETLK : F_SETLKW, &lck)) < 0 ) {
	if ( errno == EAGAIN )
	    errno = EWOULDBLOCK;
    }
    return rc;
#else
    return flock(fd, mode);
#endif
}
