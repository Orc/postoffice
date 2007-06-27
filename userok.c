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
int
userok(struct letter *let, struct address *try)
{
    struct email *em;
    DBhandle alias;
    char *value;

    if (try->user == 0 || try->user[0] == 0)
	return 1;	/* <> is alway valid; may be invalidated by
			 * higher-level code.
			 */

    if ( (alias = dbif_open(aliasfile(try->dom), DBIF_RDONLY, 0)) != 0) {
	if ( (value = dbif_get(alias, try->user)) == 0)
	    value = dbif_get(alias, lowercase(try->user));
	if ( (value==0) && isvhost(try->dom) )
	    value = dbif_get(alias, "*");

	if (value) {
	    if (try->alias = strdup(value))
		return 1;
	    else {
		syslog(LOG_ERR, "(%s) %m", try->user);
		return 0;
	    }
	}
	dbif_close(alias);
    }

    if ( (em = getemail(try)) != 0 )
	return 1;

    return 0;
}
