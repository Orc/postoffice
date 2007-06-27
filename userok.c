#include "config.h"

#include <ndbm.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <malloc.h>
#include <string.h>

#include "letter.h"
#include "aliases.h"


/*
 * check /etc/aliases, then passwd, to see if the user exists.  I check
 * /etc/aliases first because aliases override password entries.
 */
int
userok(struct letter *let, struct address *try)
{
    struct email *em;
    static DBM *alias = 0;
    datum key, value;

    if (try->user == 0 || try->user[0] == 0)
	return 1;	/* <> is alway valid; may be invalidated by
			 * higher-level code.
			 */

    if ( alias || (alias = dbm_open(PATH_ALIAS, O_RDONLY, 0)) != 0) {
	key.dptr = try->user;
	key.dsize= strlen(try->user)+1;
	value = dbm_fetch(alias, key);

	if (value.dptr == 0) {
	    key.dptr = lowercase(try->user);
	    key.dsize = strlen(key.dptr)+1;
	    value = dbm_fetch(alias, key);
	}

	if (value.dsize > 0) {
	    if (try->alias = strdup(value.dptr))
		return 1;
	    else {
		syslog(LOG_ERR, "(%s) %m", try->user);
		return 0;
	    }
	}
	/*dbm_close(alias); (try to keep the alias db open all the time) */
    }

    if ( (em = getemail(try)) != 0 )
	return 1;

    return 0;
}
