#ifndef SOCKLIB_D
#define SOCKLIB_D

#include <stdio.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <syslog.h>
#include <signal.h>
#include <setjmp.h>


jmp_buf timer_jmp;
void    timer_expired(int);

int     attach_in(struct in_addr *ip, int port);


#endif/*SOCKLIB_D*/
