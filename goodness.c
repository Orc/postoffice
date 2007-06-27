#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ndbm.h>
#include <time.h>
#include <syslog.h>
#include <sysexits.h>

#include "letter.h"

#define SANTA "/var/db/goodness"

#define VERYBAD -40

int
goodness(struct letter *let, int score)
{
    int goodness = 0;
#if WITH_COAL
    DB *db;
    datum key, contents;
    char bfr[80];
    time_t now = time(0);
    time_t then;

    if (db = dbm_open(SANTA, O_RDWR|O_CREAT, 0644) ) {
	key.dptr = let->deliveredIP;
	key.dsize= strlen(key.dptr) + 1;

	contents = dbm_fetch(db, key);

	if (contents.dptr == 0 ||
		      sscanf(contents.dptr, "%d %lu", &goodness, &then) == 0)
	    goodness = 0;

#if 0
	if ( (goodness < 0) && (then+3600 < now) )
	    goodness++;
#endif
	goodness += score;

	sprintf(bfr, "%d %lu", goodness, now);

	contents.dptr = bfr;
	contents.dsize = strlen(bfr);
	((char*)contents.dptr)[contents.dsize-1] = 0;

	dbm_store(db, key, contents, DBM_REPLACE);

	if (goodness < VERYBAD) {
	    audit(let, "QUIT", "Coal", 421);
	    syslog(LOG_INFO, "Coal for %s (%s)", let->deliveredby,
						 let->deliveredIP);
	    sprintf(bfr, "/sbin/ipfw append hard deny tcp/25 from %s",
						    let->deliveredIP);
	    system(bfr);
	    byebye(let, EX_OK);
	}
	dbm_close(db);
    }
#endif
    return goodness;
}
