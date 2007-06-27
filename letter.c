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

struct address *
parse_address(struct letter *let, char *p, char *direction)
{
    int reason;
    struct address *ret;

    if ( (ret = verify(let,p,1,&reason)) != 0)
	return ret;

    switch (reason) {
    default:
    case V_NOMX:
	message(let->out, 553, "I cannot deliver mail %s %s",
		direction, p);
	break;
    case V_WRONG:
	message(let->out, 553, "You must have a wrong number.");
	syslog(LOG_INFO, "WRONG NUMBER: %s from (%s[%s])", p,
			    let->deliveredby,let->deliveredIP);
	greylist(let, 1);
	break;
    case V_BOGUS:
	message(let->out, 555, "Unrecognisable %s address.", direction);
	break;
    case V_ERROR:
	message(let->out, 451, "System error");
	break;
    }
    return 0;
}


int
prepare(struct letter *let, FILE *in, FILE *out, struct env *e)
{
    char *p;

    memset(let, 0, sizeof *let);

    setlinebuf(let->in = in);
    setlinebuf(let->out = out);

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



static char *
skipspace(char *p)
{
    if (p) {
	while (*p && isspace(*p))
	    ++p;
    }
    return p;
}


void
greeted(struct letter *let)
{
    let->helo = 1;
}

int
from(struct letter *let, char *line)
{
    char *p;
    struct address *from;
    long left;

    if (let->from) {
	message(let->out, 550, "Too many cooks spoil the broth.");
	return 5;
    }

    p = skipspace(line+4);
    if ( strncasecmp(p, "FROM", 4) != 0 || *(p = skipspace(p+4)) != ':' ) {
	message(let->out, 501, "Badly formatted mail from: command.");
	return 5;
    }

    p = skipspace(p+1);

    if ( (from = parse_address(let, p, "from")) == 0)
	return 5;

    if ( from->local && from->user && !let->env->relay_ok ) {
	message(let->out, 553, "You are not a local client.");
	freeaddress(from);
	return 5;
    }
    else if ( (from->user == 0) && let->env->nodaemon ) {
	message(let->out, 553, "Not Allowed.");
	freeaddress(from);
	return 5;

    }
    else
	let->from = from;

    if ( (let->env->relay_ok == 0) && (left = greylist(let, 0)) > 1 ) { 
	message(let->out, 450, "System busy.  Try again in %d seconds.", left);
	freeaddress(from);
	let->from = 0;
	return 4;
    }

    /* check for esmtp mail extensions.
     */
    p += strlen(p);
    while (p > line && *--p != '>')
	;

    if (*p == '>') {

	while (*++p) {
	    while (*p && isspace(*p))
		++p;
	    if (strncasecmp(p, "size=", 5) == 0) {
		unsigned long size = atol(p+5);

		if (let->env->largest
			&& (size > let->env->largest)) {

		    message(let->out, 552,
			    "I don't accept messages longer than %lu bytes.",
			    let->env->largest);
		    freeaddress(from);
		    let->from = 0;
		    return 5;
		}
	    }
	    else if (strncasecmp(p, "body=", 5) == 0)
		; /* body=<something>.  We don't care.  */

	    while (*p && !isspace(*p))
		++p;
	}
    }

    return 2;
}

int
to(struct letter *let, char *line)
{
    char *p = skipspace(line+4);
    char *result;
    int len;
    char *q;
    char *temp;
    struct address *a;
    struct iplist mxes;
    int rc = 0;

    if (strncasecmp(p, "TO", 2) != 0 || *(p = skipspace(p+2)) != ':') {
	message(let->out, 501, "Badly formatted rcpt to: command.");
	return 0;
    }

    if ( (a = parse_address(let, p=skipspace(p+1), "to")) == 0) return 0;

    if (a->user == 0)
	message(let->out, 555, "Who?");
    else if (a->local || let->env->relay_ok) {
	if ((rc = recipients(let, a)) < 0) {
	    message(let->out, 451, "System error.");
	    rc = 0;
	}
	else if (rc == 0)
	    message(let->out, 555, "Who?");
    }
    else
	message(let->out, 502, "You may not relay through this server.");

    freeaddress(a);
    return rc;
}


int
data(struct letter *let)
{
#define CRLF	0x100
    register c = 0;
    register c1 = CRLF;
    register c2 = 0;

    if (mkspool(let) == 0) {
	message(let->out, 451,
		"Cannot store message body. Try again later.");
	return 0;
    }

    message(let->out, 354, "Bring it on.");

    while (1) {
	alarm(let->env->timeout);

	if ( (c = fgetc(let->in)) == EOF) {
	    syslog(LOG_ERR, "EOF during DATA from %s", let->deliveredby);
	    message(let->out, 451, "Unexpected EOF?");
	    break;
	}
	else if (c == '\r') {
	    if ( (c = fgetc(let->in)) == '\n')
		c = CRLF;
	    else {
		fputc('\r', let->body);
	    }
	}
	else if ( c == '\n')	/* let \n stand in for \r\n */
	    c = CRLF;

	if (c2 == CRLF && c1 == '.') {
	    if (c == CRLF) {
		alarm(0);
		return examine(let);
	    }
	    else
		c2 = 0;
	}

	if (c2) {
	    if ( fputc( (c1 == CRLF) ? '\n' : c1, let->body) == EOF ) {
		syslog(LOG_ERR, "spool write error: %m");
		message(let->out, 451,
		    "Cannot store message body. Try again later.");
		break;
	    }
	}
	c2 = c1;
	c1 = c;
    }
    alarm(0);
    reset(let);
    return 0;
}


int
post(struct letter *let)
{
    int ok, didmsg=0;
    char *ptr;

    if (svspool(let) == 0)
	return 0;

    ok = (runlocal(let) == let->local.count) && !let->fatal;

    if ( !ok ) {
	/* something went wrong.  Report it */
	char *ptr;
	size_t size;

	fseek(let->log, SEEK_END, 0);

	if (let->log && (ptr = mapfd(fileno(let->log), &size)) ) {
	    message(let->out, 552, "Local mail delivery failed:\n%.*s",
		    size, ptr);
	    munmap(ptr, size);
	    didmsg = 1;
	}
	if (!didmsg)
	    message(let->out, 552,
		    let->fatal ? "Catastrophic error delivering local mail!"
			       : "Local mail delivery failed!");

	if (let->fatal)
	    byebye(let, EX_OSERR);
    }

    reset(let);
    return ok;
}


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

    if ( (pwd = getpwnam(u->user)) == 0 )
	pwd = getpwnam(lowercase(u->user));

    if (pwd == 0)
	return 0;

    ret.user = pwd->pw_name;
    ret.domain = u->domain;
    ret.forward = 0;
    ret.uid = pwd->pw_uid;
    ret.gid = pwd->pw_gid;

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
