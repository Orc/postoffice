#include "config.h"

#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <string.h>
#if OS_FREEBSD
#   include <stdlib.h>
#else
#   include <malloc.h>
#endif

#include "letter.h"
#include "dbif.h"


/*
 * check /etc/aliases, then passwd, to see if the user exists.  I check
 * /etc/aliases first because aliases override password entries.
 */
static int
_see(struct letter *let, struct address *try, DBhandle alias)
{
    struct email *em;
    char *value = 0;

    if ( alias && ((value = dbif_get(alias, try->user)) == 0) )
	value = dbif_get(alias, lowercase(try->user));

    if ( (value == 0) && (em = getemail(try)) != 0 )
	return 1;

    if ( (value == 0) && alias && isvhost(try->dom) )
	value = dbif_get(alias, "*");

    if (value) {
	if (try->alias = strdup(value))
	    return 1;
	else
	    syslog(LOG_ERR, "(%s) %m", try->user);
    }

    return 0;
}


int
userok(struct letter *let, struct address *try)
{
    DBhandle alias;
    int rc;

    if (try->user == 0 || try->user[0] == 0)
	return 1;	/* <> is alway valid; may be invalidated by
			 * higher-level code.
			 */

    rc = _see(let, try, alias=dbif_open(aliasfile(try->dom), DBIF_READER, 0));

    if (alias) dbif_close(alias);

    return rc;
}
