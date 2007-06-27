#ifndef __SMTP_D
#define __SMTP_D

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/telnet.h>

#include "env.h"

void
smtp(FILE *, FILE *, struct sockaddr_in*, ENV*);

#endif/*__SMTP_D*/
