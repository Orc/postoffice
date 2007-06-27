#include "config.h"
#include "dbif.h"
#include "letter.h"

#include <time.h>
#include <syslog.h>
#include <sysexits.h>

#define SANTA "/var/db/goodness"

#define VERYBAD -40

int
goodness(struct letter *let, int score)
{
    int goodness = 0;
#if WITH_COAL
    DBhandle db;
    char *data;
    char bfr[80];
    time_t now = time(0);
    time_t then;

    if (db = dbif_open(SANTA, DBIF_RDWR|DBIF_CREAT, 0644) ) {

	if ( (data = dbif_get(db,let->deliveredIP)) == 0 ||
		      sscanf(data, "%d %lu", &goodness, &then) == 0)
	    goodness = 0;

#if 0
	if ( (goodness < 0) && (then+3600 < now) )
	    goodness++;
#endif
	goodness += score;

	sprintf(bfr, "%d %lu", goodness, now);

	dbif_put(db, let->deliveredIP, bfr, DBIF_REPLACE);
	dbif_close(db);

	if (goodness < VERYBAD) {
	    audit(let, "QUIT", "Coal", 421);
	    syslog(LOG_INFO, "Coal for %s (%s)", let->deliveredby,
						 let->deliveredIP);
	    sprintf(bfr, "/sbin/ipfw append hard deny tcp/25 from %s",
						    let->deliveredIP);
	    system(bfr);
	    byebye(let, EX_OK);
	}
    }
#endif
    return goodness;
}
