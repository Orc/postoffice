/* expire records out of the greylist
 */

#include "config.h"

#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include "dbif.h"

#if HAVE_LIBGEN_H
#include <libgen.h>
#endif
#if !HAVE_BASENAME
#include <string.h>
#endif

#include <stdlib.h>
#include <string.h>


int verbose = 0;
int nulluser = 0;
int dryrun = 0;
int listing = 0;
int unretried = 0;
int everybody = 0;
int prettyprint;

time_t now;

void
badinterval(char *pgm, char *arg)
{
    fprintf(stderr, "%s: bad expire interval (%s)\n", pgm, arg);
    exit(1);
}


void
list(DBhandle db, long age)
{
    char *key, *value;
    time_t delay, last;
    int ct, isblacklist;
    char bfr[80];

    for (key = dbif_findfirst(db); key; key = dbif_findnext(db,key)) {
	printf( prettyprint ? "%-31.31s\t" : "%s\t", key);

	if ( value = dbif_get(db,key) ) {
	    delay = 0;
	    last = 0;

	    if (value[0] == '*') {
		isblacklist = 1;
		ct = sscanf(value, "* %ld", &last);
		if (ct == 1) {
		    ct = 2;
		    delay = last;
		}
	    }
	    else {
		isblacklist = 0;
		ct = sscanf(value, "%ld %ld", &delay, &last);
	    }

	    if (ct >= 1) {
		if (isblacklist)
		    fputs("**** blacklist ****", stdout);
		else {
		    strftime(bfr, sizeof bfr, "<%H:%M %d %b %Y>",
						localtime(&delay));
		    fputs(bfr, stdout);
		}

		if (ct == 2) {
		    putchar(' ');
		    putchar( (last > delay) ? '#' : ' ' );
		    strftime(bfr, sizeof bfr, "<%H:%M %d %b %Y>",
						 localtime(&last));
		    fputs(bfr, stdout);
		}
		putchar('\n');
		continue;
	    }
	}
	printf("NO VALUE SET\n");
    }
}


void
scrub(DBhandle db, long age)
{
    char *key, *value;
    time_t delay, last;
    int old =0,
	gone,
	total,
	ct;

    do {
	gone = total = 0;
	bzero(&key, sizeof key);
	for (key = dbif_findfirst(db); key; key = dbif_findnext(db,key)) {
	    total++;
	    if ( (value = dbif_get(db, key)) != 0 ) {
		if ( value[0] == '*' ) {
		    if (!everybody) continue;

		    ct = sscanf(value, "* %ld", &last);
		    if (ct == 1) {
			delay = last;
			ct = 2;
		    }
		}
		else
		    ct = sscanf(value, "%ld %ld", &delay, &last);

		switch (ct) {
		case 1: last = delay;
		case 2: if (last+age < now) {
		default:    gone++;
			    if (dryrun || verbose)
				printf("delete [%s]\n", key);

			    if (!dryrun)
				dbif_delete(db, key);
			}
			else if ( nulluser && !strncmp(key, "<>@", 3) ) {
			    gone++;
			    if (dryrun || verbose)
				printf("delete [%s]\n", key);

			    if (!dryrun)
				dbif_delete(db, key);
			}
			else if ((last < delay) && unretried) {
			    gone++;
			    if (dryrun || verbose)
				printf("delete [%s]\n", key);

			    if (!dryrun)
				dbif_delete(db,key);
			}
			break;
		}
	    }
	}
	old += gone;
    } while ( (gone > 0) && !dryrun );

    if (verbose)
	printf("%d record%s; expired %d.\n", total, (total!=1)?"s":"", old);
}


void
approve(DBhandle db, char *key, int blacklist)
{
    char *value;
    char bfr[80];
    time_t delay, last;

    if (blacklist) {
	time(&last);
	snprintf(bfr, sizeof bfr, "* %ld", last);
	dbif_put(db, key, bfr, DBIF_REPLACE);
    }
    else {
	if ( value = dbif_get(db,key) ) {
	    time(&delay);

	    switch (sscanf(value, "%ld %ld", &delay, &last)) { 
	    default:
		time(&last);
	    case 2:
		delay = last-1;
		break;
	    }
	}
	else {
	    time(&last);
	    delay = last-1;
	}
	snprintf(bfr, sizeof bfr, "%ld %ld", delay, last);
	dbif_put(db, key, bfr, DBIF_REPLACE);
    }
}


main(int argc, char **argv)
{
    DBhandle db;
    int opt;
    char *e;
    char *pgm;
    char *user = 0;
    long age;
    int  blacklist;

#if HAVE_BASENAME
    pgm = basename(argv[0]);
#else
    if (pgm = strrchr(argv[0], '/'))
	++pgm;
    else
	pgm = argv[0];
#endif

    prettyprint = isatty(fileno(stdout));

    opterr = 1;
    while ( (opt = getopt(argc, argv, "?a:b:Elnuvwz")) != EOF) {
	switch (opt) {
	case 'a':   user = optarg;
		    blacklist = 0;
		    break;
	case 'b':   user = optarg;
		    blacklist = 1;
		    break;
	case 'n':   dryrun = 1;
		    break;
	case 'z':   nulluser = 1;
		    break;
	case 'E':   everybody = 1;
		    break;
	case 'u':   unretried = 1;
		    break;
	case 'v':   verbose = 1;
		    break;
	case 'w':   prettyprint = 0;
		    break;
	case 'l':   listing = 1;
		    break;
	case '?':
	default:    fprintf(stderr, "usage: %s [-a user] [-b user] [-Elnvwz] age\n", pgm);
		    exit( (opt=='h') ? 0 : 1 );
	}
    }

    argc -= optind;
    argv += optind;

    if ( (age = strtol((argc<1)?"14d":argv[0], &e, 10)) > 0 ) {
	if (e[0] && !e[1]) {
	    switch (e[0]) {
	    default:	badinterval(pgm,argv[0]);
			exit(1);
	    case 'w':
	    case 'W':	age *= 7;
	    case 'd':
	    case 'D':	age *= 24;
	    case 'h':
	    case 'H':	age *= 60;
	    case 'M':
	    case 'm':	age *= 60;
	    }
	}
	else if (age < 60) {
	    fprintf(stderr, "%s: the expiration age needs to be at least 60 seconds\n", pgm);
	    exit(1);
	}
    }
    else
	badinterval(pgm,argv[0]);

    db = dbif_open("/var/db/smtpauth", listing?DBIF_READER:DBIF_WRITER, 0600);
    if (db == 0) {
	perror("cannot open the greylist");
	exit(1);
    }

    time(&now);

    if (user)
	approve(db,user, blacklist);
    else if (listing)
	list(db, age);
    else
	scrub(db, age);
    dbif_close(db);
    exit(0);
}
