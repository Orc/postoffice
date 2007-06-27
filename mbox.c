#include "config.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <syslog.h>
#include <stdarg.h>
#include <string.h>

#include "mbox.h"
#include "socklib.h"

#if HAVE_LIMITS_H
#   include <limits.h>
#endif

#if HAVE_MALLOC_H
#   include <malloc.h>
#else
#   include <stdlib.h>
#endif

#include "mbox.h"
#include "mx.h"

void dump_session(MBOX *ses);

static void
greet(MBOX *f, char *line)
{
    if (strstr(line, "ESMTP"))
	f->esmtp = 1;
}

static void
getsize(MBOX *f, char *line)
{
    char *p = strstr(line, "SIZE");

    if (p) {
	f->size = atol(p+4);
	f->sizeok = 1;
    }
}


MBOX *
newmbox(struct in_addr *ip, int port, int verbose)
{
    struct servent *p;
    char *c, *host;
    MBOX *ret = calloc(sizeof *ret, 1);

    if (ret == 0)
	return 0;

    if ((ret->log = tmpfile()) == 0) {
	syslog(LOG_ERR, "tmpfile(): %m");
	return freembox(ret);
    }

    ret->verbose = verbose;
    memcpy(&ret->ip, ip, sizeof *ip);

    if ( (host = ptr(ip)) == 0 )
	host = inet_ntoa(*ip);

    setproctitle("connecting to %s", host);

    if ( (ret->fd = attach_in(ip, port)) != -1 ) {
	setproctitle("connected to %s", host);

	ret->opened = 1;
	if ( (ret->in = fdopen(ret->fd,"r"))
	  && (ret->out = fdopen(ret->fd,"w")) ) {
	    setlinebuf(ret->in);
	    setlinebuf(ret->out);
	    if (ret->verbose)
		fprintf(stderr, "%15s OPEN\n", inet_ntoa(ret->ip));
	    return ret;
	}
	syslog(LOG_ERR, "fdopen()s: %m");
    }
    return freembox(ret);
}


MBOX*
freembox(MBOX *p)
{
    if (p) {
	if (p->verbose && p->opened)
	    fprintf(stderr, "%15s CLOSE\n", inet_ntoa(p->ip));
	if (p->in) fclose(p->in);
	if (p->out)fclose(p->out);
	if (p->log)fclose(p->log);
	if (p->fd != -1) close(p->fd);
	free(p);
    }
    return (MBOX*)0;
}


char *
readmbox(MBOX *f)
{
    static char *buf = 0;
    static int alloc = 0,
               base  = 0,
	       len   = 0;

    int c;

    len = 0;

    while ( (c = fgetc(f->in)) != EOF && c != '\n') {
	if (c == '\r')
	    continue;

	if (len >= alloc-1) {
	    alloc = len + 100;
	    buf = buf ? realloc(buf, alloc) : malloc(alloc);
	    if (buf == 0) {
		syslog(LOG_ERR, "readmbox: %m");
		return 0;
	    }
	}
	buf[len++] = c;
    }
    if (buf) buf[len] = 0;

    return buf;
}

int
writembox(MBOX *f, char *fmt, ...)
{
    va_list ptr;
    void (*oldalarm)(int);
    int ret = 0;

    if ( (f == 0) || feof(f->out) )
	return 0;

    va_start(ptr, fmt);

    if (f->verbose) {
	fprintf(stderr, "%15s << ", inet_ntoa(f->ip));
	vfprintf(stderr, fmt, ptr);
	fputc('\n', stderr);
    }

    oldalarm = signal(SIGALRM, timer_expired);

    if (setjmp(timer_jmp) == 0) {
	alarm(600);
	vfprintf(f->out, fmt, ptr);
	fputs("\r\n", f->out);
	fflush(f->out);
	alarm(0);
	ret = !ferror(f->out);
    }
    else {
	fclose(f->out); f->out = 0;
	fclose(f->in);  f->in  = 0;
	ret = 0;
    }
    signal(SIGALRM, oldalarm);

    va_end(ptr);
    return ret;
}


char replytext[80];

static void
whynot(char *text)
{
    if ( text && *text && (replytext[0] == 0) )
	strncpy(replytext, text, sizeof replytext);
}


int
reply(MBOX *f, void (*look)(MBOX*,char *))
{
    char *line;
    char *e;
    int code;
    int first=1;

    if (f == 0) return 0;

    do {
	if ( ((line = readmbox(f)) == 0) || feof(f->in) )
	    return 0;

	code = strtol(line, &e, 10) / 100;

	if (look)
	    (*look)(f,line);

	if (first) {
	    first=0;
	    if (code == 4)
		whynot(line);
	}
	if (f->verbose)
	    fprintf(stderr, "%15s >> %s\n", inet_ntoa(f->ip), line);
	if (f->log)
	    fprintf(f->log, "\t%s\n", line);
    } while (*e == '-');
    return code;
}


#ifndef NR_CACHE
#  define NR_CACHE 4
#endif

static struct mbox_cache cache[NR_CACHE];


static int
reset(int sess)
{
/* vSMTPv */
    int code;

    writembox(cache[sess].session, "RSET");

    code = reply(cache[sess].session, 0);

    if (code == 2)
	return 1;
    if (code != 0) {
	writembox(cache[sess].session, "QUIT");
	reply(cache[sess].session, 0);
    }
/* ^SMTP^ */
    cache[sess].session = freembox(cache[sess].session);
    return 0;
}


MBOX *
session(ENV *env, char *host, int port)
{
    struct iplist mxes;
    int i, j;
    int lowest = INT_MAX;
    int victim = 0;
    struct mbox_cache *ses;

    /* first see if this host in in the cache */
    for (i = NR_CACHE; i-- > 0; )
	if (cache[i].session && (strcmp(cache[i].host, host) == 0) && reset(i))
	    return cache[i].session;

    /* then pick up the MXes for this host and see if
     * any of them match a cached MX
     */
    getMXes(host, &mxes);
    if (mxes.count == 0)
	return 0;

    for (i = mxes.count; i-- > 0; )
	for (j=NR_CACHE; j-- > 0; )
	    if (cache[j].session && (cache[j].mx.s_addr==mxes.a[i].addr.s_addr)
			     && reset(j))
		return cache[j].session;

    for (i = NR_CACHE; i-- > 0; )
	if (cache[i].session == 0) {
	    victim = i;
	    break;
	}
	else if (cache[i].prio < lowest) {
	    victim = i;
	    lowest = cache[i].prio;
	}

    ses = &cache[victim];
    for (i=NR_CACHE; i-- > 0; )
	if (i != victim)
	    cache[i].prio--;

    if (ses->session) {
/* vSMTPv */
	writembox(ses->session, "QUIT");
	reply(ses->session, 0);
/* ^SMTP^ */
    }
    ses->session = freembox(ses->session);

    for (i=mxes.count; i-- > 0; )
	if (ses->session = newmbox(&mxes.a[i].addr, port, env->verbose)) {
	    ses->mx = mxes.a[i].addr;
	    ses->host = strdup(host);
	    ses->prio = 1;
/* vSMTPv */
	    if (reply(ses->session, greet) == 2) {
		writembox(ses->session, "EHLO %s", env->localhost);
		if (reply(ses->session, getsize) != 2) {
		    writembox(ses->session, "HELO %s", env->localhost);
		    reply(ses->session, 0);
		}
		return ses->session;
	    }
	    dump_session(ses->session);
/* ^SMTP^ */
	}
	else
	    whynot(strerror(errno));

    return 0;
}


void
dump_session(MBOX *ses)
{
    int i;

    for (i=NR_CACHE; i-- > 0; )
	if (cache[i].session == ses) {
	    cache[i].session = freembox(cache[i].session);
	    return;
	}
}


void
close_sessions()
{
    int i;

    for (i=NR_CACHE; i-- > 0; )
	if (cache[i].session) {
/* vSMTPv */
	    writembox(cache[i].session, "QUIT");
	    reply(cache[i].session, 0);
/* ^SMTP^ */
	    cache[i].session = freembox(cache[i].session);
	}
}



#ifdef DEBUG_MBOX
struct in_addr localhost = { 0x0100007f };

main(int argc, char **argv)
{
    MBOX *foo;
    int i;
    int code;
    ENV env;

    env.verbose = 1;
    env.localhost = "tsfr.org";

    for (i=1; i < argc; i++) {
	fprintf(stderr, "[%s]::\n", argv[i]);
	if (foo = session(&env, argv[i], 25)) {
	    writembox(foo, "HELP");
	    reply(foo, 0);
	}
    }
    close_sessions();
}
#endif
