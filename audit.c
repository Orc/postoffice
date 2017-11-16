#include <stdio.h>
#include <syslog.h>
#include <signal.h>
#include <time.h>

#include "audit.h"

/*
 * write audit records in the form
 *    AUDIT:time-since-startup:cmd*4:code*3:rest-of-line
 * syslog should provide the pid for us.
 */

static int auditing = 0;


void
audit(struct letter *let, char *cmd, char *line, int code)
{
    if (code < 100)
	code = (code*100) + 99;

    if (auditing)
	syslog(LOG_DEBUG,"AUDIT:%3ld:%15.15s:%4.4s:%03d:%s\n",
			  (long)(time(0) - let->posted), let->deliveredIP,
			  cmd, code, line);
}

void
auditon(int sig)
{
    auditing = 1;
    syslog(LOG_INFO, "Auditing on");
    signal(SIGUSR1, auditoff);
}


void
auditoff(int sig)
{
    auditing = 0;
    syslog(LOG_INFO, "Auditing off");
    signal(SIGUSR1, auditon);
}
