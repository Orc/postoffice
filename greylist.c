#include "config.h"
#include "letter.h"
#include "dbif.h"

#include <syslog.h>

#define GREYLIST "/var/db/smtpauth"

#define WINDOW 600	/* 10 minutes windows for mail from <> */


/* returns the # of seconds left until the address is no longer
 * greylisted
 */
int
greylist(struct letter *let, int delete)
{
#ifdef WITH_GREYLIST
    DBhandle db;
    char *value;
    char *key;	/* let->from->user + @ + let->deliveredIP */
    time_t now, delay;
    int mode,status;
    int mailerdaemon = 0;
    int multiplier = 1;
    char dates[80];

    time(&now);

    if ( (db = dbif_open(GREYLIST, DBIF_RDWR|DBIF_CREAT, 0600)) == 0) {
	syslog(LOG_ERR, "Cannot open greylist database %s: %m", GREYLIST);
	return 0;	/* fail open */
    }

    if (let->from && let->from->user) {
	char *p;

	key = alloca(strlen(let->from->user) + strlen(let->deliveredIP) + 10);
	if (key)
	    sprintf(key, "%s@[%s]", let->from->user, let->deliveredIP);

	for (p = let->from->user; *p; ++p)
	    if (*p <= ' ' || !isprint(*p))
		multiplier++;
    }
    else {
	mailerdaemon = 1;
	multiplier += 4;
	if (key = alloca(strlen(let->deliveredIP) + 10))
	    sprintf(key, "<>@[%s]", let->deliveredIP);
    }

    if (strcmp(let->deliveredIP, let->deliveredby) == 0)
	multiplier ++;

    if (key == 0) {
	syslog(LOG_ERR, "Cannot build key: %m");
	return 0;
    }


    if (delete) {
	dbif_delete(db, key);
	status = let->env->delay;
    }
    else {
	if ( (value = dbif_get(db, key)) != 0 ) {

	    delay = atol(value);

	    status = (now > delay) ? 0 : delay-now;

	    if (mailerdaemon && (status == 0) && (now-delay < WINDOW) ) {
		dbif_delete(db, key);
		dbif_close(db);
		return 0;
	    }
	    mode = DBIF_REPLACE;
	}
	else {
	    mode = DBIF_INSERT;
	    status = multiplier * let->env->delay;
	    delay = now + status;
	}
	sprintf(dates, "%ld %ld", delay-10, now);

	if (dbif_put(db, key, dates, mode) != 0)
	    syslog(LOG_ERR, "Cannot %s %s in greylist",
			    (mode==DBIF_INSERT) ? "insert" : "update", key);
    }
    dbif_close(db);

    return status;
#else
    return 0;
#endif
}
