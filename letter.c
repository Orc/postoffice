#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <syslog.h>
#include <sysexits.h>
#if HAVE_ALLOCA_H
#   include <alloca.h>
#endif

#if HAVE_MALLOC_H
#   include <malloc.h>
#endif

#include "letter.h"
#include "env.h"
#include "mx.h"
#include "spool.h"
#include "domain.h"
#include "public.h"
#include "mymalloc.h"


void
byebye(struct letter *let, int exitcode)
{
    reset(let);
    exit(exitcode);
}


void
reset(struct letter *let)
{
    freelist(&(let->local));
    freelist(&(let->remote));

    if (let->from)     freeaddress(let->from);
    if (let->bodytext) munmap(let->bodytext,let->bodysize);
    if (let->headtext) free(let->headtext);
    if (let->body)     fclose(let->body);
    if (let->log)      fclose(let->log);
    if (let->tempfile) unlink(let->tempfile);

    let->fatal = 0;
    let->from = 0;
    let->log = let->body = 0;
    let->bodytext = 0;
    let->bodysize = 0;
    let->headtext = 0;
    let->headsize = 0;
    let->hopcount = 0;
    let->has_headers = 0;
    let->date = 0;
    let->messageid = 0;
    let->mesgfrom = 0;
    let->mboxfrom = 0;
    let->tempfile = 0;
    let->qcomment = 0;
    let->healthy  = 1;
}


/*
 * lowercase() returns a lowercase copy of a name (truncated to 40
 *             characters)
 */
char *
lowercase(char *q)
{
    static char bfr[40];

    strlcpy(bfr, q, sizeof bfr);

    for (q=bfr; *q; ++q)
	if (isascii(*q) && isupper(*q))
	    *q = tolower(*q);

    return bfr;
}


/*
 * try to match a name in a passwd file (case not significant)
 */
struct passwd *
getpwemail(struct domain *dom, char *q)
{
    static struct passwd *p = 0;

    if (isvhost(dom))
	return getvpwemail(dom, q);

#if 0
    /* cache the most recent lookup -- works if nobody scribbles on
     * the struct passwd * that the getpwXXX() functions use
     */
    if ( p && (strcasecmp(q, p->pw_name) == 0) )
	return p;

    /* and if that fails, rewind and look through the whole passwd file
     */
#endif
    setpwent();

    while ( ( p = getpwent()) != 0)
	if (strcasecmp(q, p->pw_name) == 0)
	    return p;

    return 0;
}


/*
 * getemail() gets password information for a user and the contents
 *            of their .forward file, if one exists (owned by and only
 *            writable by the user.)
 */
struct email *
getemail(struct address *u)
{
    struct passwd *pwd;
    static struct email ret;
    static char bfr[512];
    FILE *f;
    char *forward;

    pwd = getpwemail(u->dom, u->user);

    if (pwd == 0)
	return 0;

    ret.user = pwd->pw_name;
    ret.domain = u->domain;
    ret.forward = 0;
    ret.uid = pwd->pw_uid;
    ret.gid = pwd->pw_gid;
    ret.dom = u->dom;

    if (isvhost(u->dom))
	return &ret;

    if (forward = alloca(strlen(pwd->pw_dir) + sizeof "/.forward" + 1)) {
	sprintf(forward, "%s/.forward", pwd->pw_dir);
	if ( goodfile(forward,pwd) ) {
	    if ( f = fopen(forward, "r") ) {
		char *nl;
		fgets(bfr, sizeof bfr, f);
		fclose(f);
		if ( (nl = memchr(bfr, '\n', sizeof bfr)) && (nl > bfr) ) {
		    /* only accept the contents of a .forward if it's a
		     * properly formed line that's <= the bufsize
		     */
		    *nl = 0;
		    ret.forward = bfr;
		}
	    }
	}
    }
    else
	syslog(LOG_ERR, "getemail(%s): %m", u->full);
    return &ret;
}


int
prepare(struct letter *let, FILE *in, FILE *out, struct env *e)
{
    memset(let, 0, sizeof *let);

    let->healthy = 1;

#if HAVE_SETLINEBUF
    if (let->in = in)
	setlinebuf(let->in);
    if (let->out = out)
	setlinebuf(let->out);
#else
    let->in = in;
    let->out = out;
#endif

    let->env = e;
    time(&let->posted);
    sprintf(let->qid, "%07x", getpid());

    return 1;
}


char *
skipspace(char *p)
{
    if (p) {
	while (*p && isspace(*p))
	    ++p;
    }
    return p;
}
