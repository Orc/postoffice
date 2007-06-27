/*
 * smtp gateway server
 */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <netdb.h>
#include <syslog.h>
#include <ctype.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <setjmp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sysexits.h>

#ifdef WITH_TCPWRAPPERS
#include <tcpd.h>

int deny_severity = 0;
int allow_severity = 0;
#endif

#include "letter.h"
#include "smtp.h"
#include "env.h"
#include "mx.h"

enum cmds { HELO, EHLO, MAIL, RCPT, DATA, RSET,
            VRFY, EXPN, QUIT, NOOP, DEBU, MISC };

#define CMD(t)	{ t, #t }
struct cmdt {
    enum cmds code;
    char text[4];
} cmdtab[] = {
    CMD(HELO),
    CMD(EHLO),
    CMD(MAIL),
    CMD(RCPT),
    CMD(DATA),
    CMD(RSET),
    CMD(VRFY),
    CMD(EXPN),
    CMD(QUIT),
    CMD(DEBU),
    CMD(NOOP),
};
#define NRCMDS	(sizeof cmdtab/sizeof cmdtab[0])

static enum cmds
cmd(char *line)
{
    int i;
    for (i=0; i < NRCMDS; i++)
	if (strncasecmp(line, cmdtab[i].text, 4) == 0)
	    return cmdtab[i].code;
    return MISC;
}

static void
psstat(struct letter *let, char *action)
{
    if (let && let->env && let->env->argv0) {
	sprintf(let->env->argv0,
		"SMTP %.4s %s                  ",
		action, let->deliveredby);
    }
}



/*
 * write a message to the client, linewrapping at 70 columns.
 */
void
message(FILE *f, int code, char *fmt, ...)
{
    va_list ptr;
    static char bfr[10240];
    int size;
    int i, j, k;
    int dash = (code < 0);

    va_start(ptr, fmt);
    size = vsnprintf(bfr, sizeof bfr, fmt, ptr);
    va_end(ptr);

    if (dash) code = -code;

    for (i=0; i < size; i = j+1) {
	for (j=i; j < i+70 && j < size && bfr[j] != '\n'; j++)
	    ;
	if ( (j >= i + 70) && !isspace(bfr[j]) ) {
	    do {
		--j;
	    } while ( (j > i) && !isspace(bfr[j]) );

	    if (j == i)
		j = i + 70;
	}

	fprintf(f, "%03d%c", code, (dash || (j<size-1)) ? '-' : ' ');
	for ( ;i < j; i++)
	    fputc(toupper(bfr[i]), f);
	fputs("\r\n", f);
	fflush(f);
    }
}


static jmp_buf bye;

static void
zzz(int signo)
{
    longjmp(bye, signo);
}


static int
smtpbugcheck(struct letter *let)
{
    int code = virus_scan(let);
    char *msg;
    char *p, *q;
    size_t size;
    int count;

    if (code) {
	fseek(let->log, 0, SEEK_END);
	fputc(0, let->log);
	rewind(let->log);
	greylist(let, 1);

	if ( (let->log != stderr) && (msg = mapfd(fileno(let->log), &size)) ) {
	    message(let->out,-code, "This mail message contains germs");
	    message(let->out, code, "%.*s", size, msg);

	    greylist(let, 1);
	    for (p = msg; q = strchr(p, '\n'); p = 1+q) {
		syslog(LOG_ERR, "VIRUS from (%s,%s): %.*s",
				let->deliveredby, let->deliveredIP,
				(int)(q-p), p);
	    }
	    munmap(msg, size);
	}
	else {
	    message(let->out, code, "Do you, my poppet, feel infirm?\n"
				    "I do believe you contain a germ.");
	    syslog(LOG_ERR, "VIRUS from (%s,%s)",
			    let->deliveredby, let->deliveredIP);
	}
	return 0;
    }
    return 1;
}


static struct address *
parse_address(struct letter *let, char *p, int to)
{
    int reason;
    struct address *ret;

    if ( (ret = verify(let,p,1,&reason)) != 0)
	return ret;

    switch (reason) {
    default:
    case V_NOMX:
	message(let->out, 553, to ? "I cannot deliver mail to %s"
				  : "I do not accept mail from %s", p);
	break;
    case V_WRONG:
	message(let->out, 553, "You must have a wrong number.");
	syslog(LOG_INFO, "WRONG NUMBER: %s from (%s[%s])", p,
			    let->deliveredby,let->deliveredIP);
	greylist(let, 1);
	break;
    case V_BOGUS:
	message(let->out, 555, "Unrecognisable %s address.", to?"to":"from");
	break;
    case V_ERROR:
	message(let->out, 451, "System error");
	break;
    }
    return 0;
}


static int
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

    if ( (from = parse_address(let, p, 0)) == 0)
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


static int
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

    if ( (a = parse_address(let, p=skipspace(p+1), 1)) == 0) return 0;

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


static int
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


static int
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


static int
helo(struct letter *let, enum cmds cmd, char *line)
{
    int i;
    struct iplist list;
    char *p;

    let->helo = 1;
    if (let->env->checkhelo && !let->env->relay_ok) {

	if (p = strchr(line, '\n')) {
	    /* trim trailing spaces */
	    while (p > line && isspace(p[-1]) )
		--p;
	    *p = 0;
	}

	if (getIPa(p=skipspace(line+4), &list) > 0) {
	    for (i=0; i < list.count; i++)
		if (islocalhost(let->env, &(list.a[i].addr))) {
		    audit(let, (cmd==HELO)?"HELO":"EHLO", line, 503);
		    message(let->out, 503, "Liar, liar, pants on fire!");
		    freeiplist(&list);
		    return 0;
		}
	    freeiplist(&list);
	}
    }
    return 1;
}


static void
debug(struct letter *let)
{
    int i;
    ENV *env = let->env;

    audit(let, "DEBU", "", 250);
    if (let->from)
	message(let->out,-250,"From:<%s> /%s/%s/local=%d/alias=%s/",
		    let->from->full,
		    let->from->user,
		    let->from->domain,
		    let->from->local,
		    let->from->alias);

    for (i=let->local.count; i-- > 0; )
	describe(let->out, 250, &let->local.to[i] );

    for (i=let->remote.count; i-- > 0; )
	describe(let->out, 250, &let->remote.to[i] );

    message(let->out,-250, "B1FF!!!!: T\n");
#if WITH_TCPWRAPPERS
    message(let->out,-250, "Tcp-Wrappers: T\n");
#endif
#if WITH_GREYLIST
    message(let->out,-250, "Greylist: T\n");
#endif
#ifdef AV_PROGRAM
    message(let->out,-250, "AV program: <%s>\n", AV_PROGRAM);
#endif
#if USE_PEER_FLAG
    message(let->out,-250, "Peer flag: T\n");
#endif
#if WITH_COAL
    message(let->out,-250, "Coal: T\n");
#endif
    if (env->largest)
	message(let->out,-250, "size: %ld", env->largest);
    message(let->out, 250, "Timeout: %d\n"
		      "Delay: %d\n"
		      "Max clients: %d\n"
		      "Qreturn: %ld\n"
		      "Relay-ok: %s\n"
		      "CheckHELO: %s\n"
		      "NoDaemon: %s\n"
		      "LocalMX: %s\n"
		      "Paranoid: %s",
			  env->timeout,
			  env->delay,
			  env->max_clients,
			  env->qreturn,
			  env->relay_ok ? "T" : "NIL",
			  env->checkhelo ? "T" : "NIL",
			  env->nodaemon ? "T" : "NIL",
			  env->localmx ? "T" : "NIL",
			  env->paranoid ? "T" : "NIL" );
}


void
smtp(FILE *in, FILE *out, struct sockaddr_in *peer, ENV *env)
{
    char line[520];	/* rfc821 says 512; better to be paranoid */
    struct letter letter;
    time_t tick = time(NULL);
    extern char *nameof(struct sockaddr_in*);
    enum cmds c;
    int ok = 1;
    int issock = 1;
    char bfr[1];
    int rc, score, traf = 0;
    int timeout = env->timeout;

    openlog("smtpd", LOG_PID, LOG_MAIL);

    if ( prepare(&letter, in, out, env) ) {
	letter.deliveredby = peer ? strdup(nameof(peer)) : env->localhost;
	letter.deliveredIP = peer ? inet_ntoa(peer->sin_addr) : "127.0.0.1";
	letter.deliveredto = env->localhost;

	if (env->paranoid && !strcmp(letter.deliveredby,letter.deliveredIP)) {
	    message(out, 421, "%s is not accepting mail from %s,"
			     " because we cannot resolve your IP address."
			     " Try again later, okay?",
			     letter.deliveredto, letter.deliveredby);
	    goodness(&letter, -2);
	    syslog(LOG_ERR, "REJECT: stranger (%s)", letter.deliveredIP);
	    audit(&letter, "CONN", "stranger", 421);
	    byebye(&letter, 1);
	}
#ifdef WITH_TCPWRAPPERS
	else if (!hosts_ctl("smtp", letter.deliveredby,
			       letter.deliveredIP, STRING_UNKNOWN)) {
	    char *why;

	    if ( (why=getenv("WHY")) == 0)
		why = "We get too much spam from your domain";

	    message(out, 554, "%s does not accept mail"
			      " from %s, because %s.", letter.deliveredto,
			      letter.deliveredby, why);
	    goodness(&letter, -2);
	    syslog(LOG_ERR, "REJECT: blacklist (%s, %s)",
				letter.deliveredby, letter.deliveredIP);
	    audit(&letter, "CONN", "blacklist", 554);
	    ok = 0;
	}
#endif

	else {
	    int fd;
	    char *blurb = 0;
	    size_t size;

	    audit(&letter, "CONN", "", 220);

	    if ( (fd = open("/etc/issue.smtp", O_RDONLY)) != -1) {
		blurb = mapfd(fd, &size);
		close(fd);
	    }

	    message(out, blurb ? -220 : 220,
			"Hello, %s, welcome to the ESMTP service on %s.\n"
			      "The current time is %s",
			    letter.deliveredby, letter.deliveredto,
			    ctime(&tick));

	    if (blurb) {
		message(out, 220, "%.*s", size, blurb);
		munmap(blurb, size);
	    }
	}
    }
    else {
	message(letter.out, 421, "System error.");
	audit(&letter, "CONN", "Error", 421);
	byebye(&letter, 1);
    }

    /* on signal, try to clean up before we leave
     */
    signal(SIGHUP, zzz);
    signal(SIGINT, zzz);
    signal(SIGQUIT, zzz);
    signal(SIGKILL, zzz);
    signal(SIGTERM, zzz);
    signal(SIGUSR1, SIG_IGN);
    signal(SIGUSR1, SIG_IGN);
    signal(SIGALRM, zzz);

    if (setjmp(bye) != 0) {
	goodness(&letter, traf ? -1 : -2);
	audit(&letter, "QUIT", "timeout", 421);
	byebye(&letter, 1);
    }

    do {
#if 0
	psstat(&letter, "EOF?");
	if (issock) {
	    if ( (rc = recv(fileno(in), bfr, 1, MSG_PEEK)) < 1) {
		if (errno == ENOTSOCK)
		    issock = 0;
		else {
		    break;
		}
	    }
	}
#endif
	score = 0;
	alarm(timeout);
	psstat(&letter, "gets");
	if (fgets(line, sizeof line, in) == 0)
	    break;

	psstat(&letter, (c = cmd(line)) == MISC ? "ERR!" : line);

	alarm(60);	/* allow 60 seconds to process a command */
	if (ok) {
	    switch (c) {
	    case EHLO:
		if (ok = helo(&letter, c, line)) {
		    message(out,-250, "Hello, Sailor!");
		    if (env->largest)
			message(out,-250, "size %ld", env->largest);
		    message(out, 250, "8bitmime");
		    audit(&letter, "EHLO", line, 250);
		}
		else
		    score = -4;
		break;

	    case HELO:
		if (ok = helo(&letter, c, line)) {
		    message(out, 250, "A wink is as good as a nod.");
		    audit(&letter, "HELO", line, 250);
		}
		else
		    score = -4;
		break;
	    
	    case MAIL:
		traf++;
		if (letter.from)	/* rfc821 */
		    reset(&letter);

		if ( (rc = from(&letter, line)) == 2 ) {
		    audit(&letter, "MAIL", line, 250);
		    message(out, 250, "Okay fine.");
		    timeout = env->timeout;
		    score = 1;
		}
		else {
		    /* After a MAIL FROM:<> fails, put the
		     * caller on a really short input timer
		     * in case their tiny brain has popped
		     * as the result of getting a non 2xx
		     * reply
		     */
		    score = -2;
		    audit(&letter, "MAIL", line, rc);
		    timeout = env->timeout / 10;
		}
		break;

	    case RCPT:
		traf++;
		if (to(&letter, line)) {
		    score = 1;
		    message(out, 250, "Sure, I love spam!");
		    audit(&letter, "RCPT", line, 250);
		}
		else {
		    score = -2;
		    audit(&letter, "RCPT", line, 5);
		}
		break;

	    case DATA:
		if (letter.from && (letter.local.count || letter.remote.count) ) {
		    traf++;

		    if ( data(&letter) ) {
			if (env->largest && (letter.bodysize > env->largest)) {
			    audit(&letter, "DATA", "size", 550);
			    message(out, 550, "I don't accept messages longer "
					    "than %lu bytes.", env->largest);
			}
			else if (letter.hopcount > env->max_hops) {
			    audit(&letter, "DATA", "looping", 550);
			    message(out, 550, "Too many Received: fields in "
					      "the message header.  Is it "
					      "looping?");
			}
			else {
			    alarm(0);
			    if (smtpbugcheck(&letter) && post(&letter) ) {
				audit(&letter, "DATA", "", 250);
				message(out, 250, "Okay fine."); 
				score = 2;
			    }
			    else {
				score = -1;
				audit(&letter, "DATA", "", 5);
			    }
			}
		    }
		    reset(&letter);
		    break;
		}
		audit(&letter, "DATA", "", 550);
		message(out, 550, "Who is it %s?", letter.from ? "TO" : "FROM");
		break;

	    case VRFY:
	    case EXPN:
		audit(&letter, line, "", (c==VRFY)?252:550);
		message(out, (c==VRFY)?252:550, "What's your clearance, Citizen?");
		break;

	    case RSET:
		audit(&letter, "RSET", "", 250);
		reset(&letter);
		message(out, 250, "Deja vu!");
		break;

	    case QUIT:
		audit(&letter, "QUIT", "", 221);
		if (!traf)
		    goodness(&letter, -1);
		message(out, 221, "Be seeing you.");
		byebye(&letter, 0);

	    case NOOP:
		audit(&letter, "NOOP", "", 250);
		message(out, 250, "Yes, yes, I know you're busy.");
		break;
	    
	    case DEBU:
		if (env->debug) {
		    debug(&letter);
		    break;
		}
		/* otherwise fall into the default failure case */
	    default:
		audit(&letter, "", line, 502);
		message(out, 502, "Sadly, No!");
		break;
	    }
	}
	else {
	    if (c == QUIT) {
		audit(&letter, "QUIT", "", 221);
		message(out,221,"Be seeing you.");
		byebye(&letter, 0);
	    }
	    else {
		audit(&letter, line, line, 503);
		sleep(30);
		message(out,503,"I'm sorry Dave, I'm afraid I can't do that.");
	    }
	}
	if (score)
	    goodness(&letter, score);
	fflush(out);
	fflush(in);
    } while ( !(feof(out) || feof(in)) );
    goodness(&letter, traf ? -1 : -2);
    audit(&letter, "QUIT", "EOF", 421);
    byebye(&letter,1);
}
