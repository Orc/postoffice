#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <ndbm.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sysexits.h>
#if OS_FREEBSD
#   include <stdlib.h>
#else
#   include <malloc.h>
#endif

#include "aliases.h"
#include "env.h"


static datum
token(char *p, char sep, char **next)
{
    datum ret;
    char *q;
    int i;

    ret.dptr = 0;
    ret.dsize = 0;

    while (isspace(*p))
	++p;

    for (q = p; *q != '\n' && *q != sep; q++)
	;
    if (*q == sep) {
	*next = q;

	/* possibly good */
	while ( (--q >= p) && isspace(*q) )
	    ;

	if (q >= p) {
	    if ( (ret.dptr = malloc(2 + (q-p))) != 0 ) {
		for (i=0; (*p != sep) && (p <= q); p++, i++) {
		    if ( isascii(*p) && isupper(*p) )
			((char*)ret.dptr)[i] = tolower(*p);
		    else
			((char*)ret.dptr)[i] = *p;
		}
		((char*)ret.dptr)[i++] = 0;
		ret.dsize = i;
	    }
	}
    }
    return ret;
}


void
newaliases(int argc, char **argv)
{
    char atemp[sizeof PATH_ATEMP+10];
    char alias[sizeof PATH_ALIAS+10];
    int fd;
    char *atext;
    size_t asize;
    int nraliases = 0;
    int longest = 0;
    int total = 0;
    int rv;
    datum key, value;
    DBM *aliasdb;
    char *q;

    strcpy(atemp, PATH_ATEMP);

    if ( !mktemp(atemp) ) {
	perror(atemp);
	exit(EX_TEMPFAIL);
    }

    if ( (aliasdb = dbm_open(atemp, O_RDWR|O_CREAT|O_EXCL, 0644)) == 0) {
	perror(atemp);
	exit(EX_NOPERM);
    }

    sprintf(atemp, "%s%s", atemp, DBM_SUFFIX);

    if ( (fd = open(PATH_ALIAS, O_RDONLY)) != -1 ) {
	if (atext = mapfd(fd, &asize)) {
	    char *p, *nl, *end;

	    for (p = atext, end = atext+asize; p && (p < end); p = 1+nl) {
		if ( (nl = memchr(p, '\n', (end-p))) == 0 )
		    break;

		key = token(p, ':', &p);

		if ( key.dptr && (((char*)key.dptr)[0] != '#') ) {

		    /* slurp in continuation lines */
		    while ( (nl < end-1) && isspace(nl[1]) ) {
			if ( (q = memchr(nl+1,'\n',(end-nl)-1)) == 0 )
			    nl = end-1;
			else
			    nl = q;
		    }
		    /* trim leading whitespace */
		    do { ++p; } while (isspace(*p) && *p != '\n');

		    /* trim trailing whitespace */
		    for (q = nl; (q > p) && isspace(*q); --q)
			;

		    value.dsize = (q-p)+2;
		    if ( (q > p) && (value.dptr = malloc(value.dsize)) != 0 ) {
			memcpy(value.dptr, p, value.dsize);
			((char*)value.dptr)[value.dsize-1] = 0;

			rv = dbm_store(aliasdb, key, value, DBM_INSERT);

			if (rv < 0) {
			    fprintf(stderr, "alias %.*s", key.dsize, key.dptr);
			    if (errno)
				fprintf(stderr, " : %s\n", strerror(errno));
			    else
				fprintf(stderr, " : db error %d\n", rv);
			    unlink(atemp);
			    exit(EX_IOERR);
			}
			nraliases++;
			if (value.dsize-1 > longest)
			    longest = value.dsize-1;
			/* don't count null bytes in the total size */
			total += (value.dsize + key.dsize - 2);
			free(value.dptr);
		    }
		}
		if (key.dptr) free(key.dptr);
	    }
	    munmap(atext, asize);
	}
	close(fd);
    }
    /* drop in a sendmail-compatable magic cookie */
    key.dptr = "@";
    key.dsize = 2;
    value.dptr = "@";
    value.dsize = 2;
    dbm_store(aliasdb, key, value, DBM_INSERT);
    dbm_close(aliasdb);

    sprintf(alias, "%s%s", PATH_ALIAS, DBM_SUFFIX);

    if (rename(atemp, alias) != 0) {
	perror(alias);
	exit(EX_IOERR);
    }
    fprintf(stderr, "%s: %d alias%s",
		    PATH_ALIAS,
		    nraliases, (nraliases != 1)?"es":"");
    if (nraliases > 1)
	fprintf(stderr, ", longest is %d byte%s", longest, (longest!=1)?"s":"");
    fprintf(stderr, ", %d byte%s total.\n", total, (total!=1)?"s":"");
}


#ifdef DEBUG

main()
{
    newaliases();
}
#endif
