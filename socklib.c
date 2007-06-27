#include "config.h"

#include "socklib.h"

jmp_buf timer_jmp;

void
timer_expired(int sig)
{
    longjmp(timer_jmp,1);
}


int
attach_in(struct in_addr *ip, int port)
{
    int fd = -1;
    struct sockaddr_in host;
    void (*oldalarm)(int);

    oldalarm = signal(SIGALRM, timer_expired);

    if (setjmp(timer_jmp) == 0) {
	alarm(300);
	if ( (fd = socket(AF_INET, SOCK_STREAM, 0)) != -1) {
	    host.sin_family = AF_INET;
	    host.sin_port = htons(port);
	    memcpy(&host.sin_addr, ip, sizeof *ip);

	    if ( connect(fd, (struct sockaddr*)&host, sizeof(host)) != 0 ) {
		close(fd);
		fd = -1;
	    }
	}
	alarm(0);
    }
    else
	errno = ETIMEDOUT;

    if ( fd == -1 )
	syslog(LOG_ERR, "attach_in(%s): %m", inet_ntoa(*ip));

    signal(SIGALRM, oldalarm);
    return fd;
}


