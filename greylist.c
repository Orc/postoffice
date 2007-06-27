#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <ndbm.h>

#include "letter.h"

#define GREYLIST "/var/db/smtpauth"

#define WINDOW 600	/* 10 minutes windows for mail from <> */


/* returns the # of seconds left until the address is no longer
 * greylisted
 */
int
greylist(struct letter *let, int delete)
{
#if WITH_GREYLIST
    DBM *db;
    datum key, value;
    char *kw;	/* let->from->user + @ + let->deliveredIP */
    time_t now, delay;
    int mode,status;
    int mailerdaemon = 0;
    int multiplier = 1;
    char dates[80];

    time(&now);

    if ( (db = dbm_open(GREYLIST, O_RDWR|O_CREAT, 0600)) == 0) {
	syslog(LOG_ERR, "Cannot open greylist database %s: %m", GREYLIST);
	return 0;	/* fail open */
    }

    if (let->from && let->from->user) {
	kw = alloca(strlen(let->from->user) + strlen(let->deliveredIP) + 10);
	if (kw)
	    sprintf(kw, "%s@[%s]", let->from->user, let->deliveredIP);
    }
    else {
	mailerdaemon = 1;
	multiplier *= 4;
	if (kw = alloca(strlen(let->deliveredIP) + 10))
	    sprintf(kw, "<>@[%s]", let->deliveredIP);
    }

    if (strcmp(let->deliveredIP, let->deliveredby) == 0)
	multiplier ++;

    if (kw == 0) {
	syslog(LOG_ERR, "Cannot build key: %m");
	return 0;
    }

    key.dptr = kw;
    key.dsize = strlen(kw);


    if (delete) {
	dbm_delete(db, key);
	status = let->env->delay;
    }
    else {
	value = dbm_fetch(db, key);

	if (value.dptr != 0) {

	    delay = atol(value.dptr);

	    status = (now > delay) ? 0 : delay-now;

	    if (mailerdaemon && (status == 0) && (now-delay < WINDOW) ) {
		dbm_delete(db, key);
		dbm_close(db);
		return 0;
	    }
	    mode = DBM_REPLACE;
	}
	else {
	    mode = DBM_INSERT;
	    status = multiplier * let->env->delay;
	    delay = now + status;
	}
	sprintf(dates, "%ld %ld", delay-10, now);
	value.dptr = dates;
	value.dsize = strlen(dates) + 1;

	if (dbm_store(db, key, value, mode) != 0)
	    syslog(LOG_ERR, "Cannot %s %s in greylist",
			    (mode==DBM_INSERT) ? "insert"
					       : "update", kw);
    }
    dbm_close(db);

    return status;
#else
    return 0;
#endif
}
