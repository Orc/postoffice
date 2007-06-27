#include "config.h"

#include <ndbm.h>
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
#include "aliases.h"


static void*
alias_open(char* file)
{
    return (void*)dbm_open(file, O_RDONLY, 0);
}


static char *
alias_lookup(void* db, char* key)
{
    datum id, value;

    id.dptr = key;
    id.dsize = strlen(key)+1;
    value = dbm_fetch((DBM*)db,id);

    return value.dptr ? value.dptr : 0;
}

static void
alias_close(void *db)
{
    dbm_close((DBM*)db);
}



/*
 * check /etc/aliases, then passwd, to see if the user exists.  I check
 * /etc/aliases first because aliases override password entries.
 */
int
userok(struct letter *let, struct address *try)
{
    struct email *em;
    static void* alias = 0;
    char *value;

    if (try->user == 0 || try->user[0] == 0)
	return 1;	/* <> is alway valid; may be invalidated by
			 * higher-level code.
			 */

#ifdef VPATH
    if (try->vhost && (value = isvhost(try->domain)) ) {
	static void *valias;
	char *vap = alloca(strlen(value) + sizeof "/aliases" + 1);

	if (vap) {
	    sprintf(vap, "%s/aliases", value);

	    if (valias = alias_open(vap)) {
		if ( (value = alias_lookup(valias, try->user)) == 0 )
		    value = alias_lookup(valias, lowercase(try->user));
		if (value == 0)
		    value = alias_lookup(valias, "*");
		alias_close(valias);

		if (value)
		    if (try->alias = strdup(value))
			return 1;
		    else {
			syslog(LOG_ERR, "(%s) %m", try->user);
			return 0;
		    }
	    }
	}
    }
    else
#endif

    if ( alias || (alias = alias_open(PATH_ALIAS)) != 0) {
	if ( (value = alias_lookup(alias, try->user)) == 0)
	    value = alias_lookup(alias, lowercase(try->user));
	if (value) {
	    if (try->alias = strdup(value))
		return 1;
	    else {
		syslog(LOG_ERR, "(%s) %m", try->user);
		return 0;
	    }
	}
	/* alias_close(alias); */
    }

    if ( (em = getemail(try)) != 0 )
	return 1;

    return 0;
}
