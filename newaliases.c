#include "config.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sysexits.h>


#if HAVE_MALLOC_H
#   include <malloc.h>
#else
#   include <stdlib.h>
#endif

#include "dbif.h"
#include "aliases.h"
#include "env.h"
#include "domain.h"


static char*
token(char *p, char sep, char **next)
{
    char *ret;
    char *q;
    int i;

    ret = 0;

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
	    if ( (ret = malloc(2 + (q-p))) != 0 ) {
		for (i=0; (*p != sep) && (p <= q); p++, i++) {
		    if ( isascii(*p) && isupper(*p) )
			ret[i] = tolower(*p);
		    else
			ret[i] = *p;
		}
		ret[i++] = 0;
	    }
	}
    }
    return ret;
}


static void
rebuild_db(char *domain)
{
    char *atemp, *alias;
    int fd;
    char *atext;
    size_t asize;
    int nraliases = 0;
    int longest = 0;
    int total = 0;
    int rv;
    char *key, *value;
    DBhandle aliasdb;
    char *q;
    struct domain *dom = getdomain(domain);

    if ( domain && (dom == 0) ) {
	fprintf(stderr, "%s: not a known virtual domain\n", domain);
	return;
    }

    alias = aliasfile(dom);
    if ( (atemp = alloca(strlen(alias) + 10)) == 0 ) {
	perror(alias);
	exit(EX_TEMPFAIL);
    }
    sprintf(atemp, "%sXXXXXX", alias);

    if ( ! mktemp(atemp) ) {
	perror(atemp);
	exit(EX_TEMPFAIL);
    }

    aliasdb = dbif_open(atemp, DBIF_WRITER|DBIF_CREAT, 0644);
    if (aliasdb == 0) {
	perror(atemp);
	exit(EX_NOPERM);
    }

    if ( (fd = open(alias, O_RDONLY)) != -1 ) {
	if (atext = mapfd(fd, &asize)) {
	    char *p, *nl, *end;
	    int size;
	    char *value;

	    for (p = atext, end = atext+asize; p && (p < end); p = 1+nl) {
		if ( (nl = memchr(p, '\n', (end-p))) == 0 )
		    break;

		key = token(p, ':', &p);

		if ( key && (key[0] != '#') ) {

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

		    size = (q-p)+2;
		    if ( (q > p) && (value = malloc(size)) != 0 ) {
			memcpy(value, p, size);
			value[size-1] = 0;

			rv = dbif_put(aliasdb,key,value,DBIF_INSERT);
			if (rv < 0) {
			    fprintf(stderr, "alias %s", key);
			    if (errno)
				fprintf(stderr, " : %s\n", strerror(errno));
			    else
				fprintf(stderr, " : db error %d\n", rv);
			    unlink(atemp);
			    exit(EX_IOERR);
			}
			nraliases++;
			if (size-1 > longest)
			    longest = size-1;
			/* don't count null bytes in the total size */
			total += (size + strlen(key) - 1);
			free(value);
		    }
		}
		if (key) free(key);
	    }
	    munmap(atext, asize);
	}
	close(fd);
    }
    /* drop in a sendmail-compatable magic cookie */
    dbif_put(aliasdb, "@", "@", DBIF_INSERT);
    dbif_close(aliasdb);

    if (dbif_rename(atemp, alias) != 0) {
	perror(alias);
	exit(EX_IOERR);
    }
    fprintf(stderr, "%s: %d alias%s",
		    alias,
		    nraliases, (nraliases != 1)?"es":"");
    if (nraliases > 1)
	fprintf(stderr, ", longest is %d byte%s", longest, (longest!=1)?"s":"");
    fprintf(stderr, ", %d byte%s total.\n", total, (total!=1)?"s":"");
}


void
newaliases(int argc, char **argv)
{
    int i;

    if (argc == 0)
	rebuild_db(0);
    else for (i=0; i< argc; i++)
	rebuild_db(argv[i]);
}



#ifdef DEBUG

main()
{
    newaliases(0);
}
#endif
