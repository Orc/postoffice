#include "config.h"

#include <stdio.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "letter.h"


/*
 * Run a virus scan on the message body and return an error string.
 */
int
virus_scan(struct letter *let)
{
#ifdef AV_PROGRAM
    struct recipient av;

    av.fullname = AV_PROGRAM;
    av.typ = emEXE;
    av.user = av.host = 0;

    av.uid = NOBODY_UID;
    av.gid = NOBODY_GID;
    if (! (let->log || (let->log = tmpfile())) ) {
	syslog(LOG_ERR, "Cannot create transaction log: %m");
	let->log = stderr;
    }

    if (exe(let, &av) == 0)
	return WIFEXITED(let->status) ? 550 : 450;

#endif
    return 0;
}
