#include "config.h"

#include <string.h>
#include <ctype.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <syslog.h>
#include <sysexits.h>
#if OS_FREEBSD
#   include <stdlib.h>
#else
#   include <malloc.h>
#endif

#include "letter.h"
#include "env.h"
#include "mx.h"
#include "spool.h"


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
    let->date = 0;
    let->messageid = 0;
    let->mesgfrom = 0;
    let->mboxfrom = 0;
    let->tempfile = 0;
    let->qcomment = 0;
}


/*
 * lowercase() returns a lowercase copy of a name (truncated to 40
 *             characters)
 */
char *
lowercase(char *q)
{
    static char bfr[40];

    strncpy(bfr, q, sizeof bfr);
    bfr[sizeof(bfr)-1] = 0;

    for (q=bfr; *q; ++q)
	if (isascii(*q) && isupper(*q))
	    *q = tolower(*q);

    return bfr;
}


/*
 * try to match a name in /etc/passwd (case not significant)
 */
struct passwd *
getpwemail(char *q)
{
    static struct passwd *p = 0;

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
    static char bfr[200];
    int fd;
    struct stat st;
    char *forward;
    char *p;

#ifdef VPATH
    if (u->vhost)
	pwd = getvpwemail(u->user, u->domain);
    else
	pwd = getpwemail(u->user);
#else
    pwd = getpwemail(u->user);
#endif

    if (pwd == 0)
	return 0;

    ret.user = pwd->pw_name;
    ret.domain = u->domain;
    ret.forward = 0;
    ret.uid = pwd->pw_uid;
    ret.gid = pwd->pw_gid;

#ifdef VPATH
    if (u->vhost)
	return &ret;
#endif

    if (forward = alloca(strlen(pwd->pw_dir) + sizeof "/.forward" + 1)) {
	sprintf(forward, "%s/.forward", pwd->pw_dir);
	if (stat(forward, &st) == 0 && st.st_uid == ret.uid
				    && (st.st_mode & (S_IWGRP|S_IWOTH)) == 0 ) {
	    if ( (fd = open(forward, O_RDONLY)) != -1) {
		if (read(fd, bfr, sizeof bfr) > 0)
		    ret.forward = bfr;
		close(fd);
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
    char *p;

    memset(let, 0, sizeof *let);

    if (let->in = in)
	setlinebuf(let->in);
    if (let->out = out)
	setlinebuf(let->out);

    let->env = e;
    time(&let->posted);
    sprintf(let->qid, "%07x", getpid());

    return 1;
}


int
pending(struct list L)
{
    int i;
    int active = 0;

    for (i=0; i < L.count; i++)
	if (L.to[i].status == PENDING)
	    ++active;

    return active;
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
