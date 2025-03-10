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
#include <sys/utsname.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sysexits.h>
#include <fcntl.h>

#ifdef WITH_TCPWRAPPERS
#include <tcpd.h>

int deny_severity = 0;
int allow_severity = 0;
#endif

#include "letter.h"
#include "smtp.h"
#include "env.h"
#include "mx.h"
#include "mf.h"
#include "audit.h"
#include "public.h"
#include "mymalloc.h"
#include "spool.h"

extern char myversion[];

#define do_reset(x)	mfreset(x),reset(x)

enum cmds { HELO, EHLO, MAIL, RCPT, DATA, RSET,
            VRFY, EXPN, QUIT, NOOP, DEBU, MISC,
	    AUTH };

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
#if SMTP_AUTH
    CMD(AUTH),
#endif
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
    setproctitle("SMTP %.4s %s", action, let->deliveredby);
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
    int i, j;
    int dash = (code < 0);
    int shout = 1;

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
	for ( ;i < j; i++) {
	    if (bfr[i] == '<')
		--shout;
	    else if (bfr[i] == '>')
		++shout;
	    else
		fputc(shout ? toupper(bfr[i]) : bfr[i], f);
	}
	fputs("\r\n", f);
	fflush(f);
    }
}


static int
purge(int fd)
{
    int flags;
    char bfr[256];
    int size;
    int eaten=0;

    if ( (flags = fcntl(fd, F_GETFL)) == -1 )
       return 0;

    if ( fcntl(fd, F_SETFL, O_NONBLOCK) == -1 )
       return 0;

    sleep(1);
    while ( (size = read(fd, bfr, 256)) > 0 ) {
       eaten += size;
    }

    fcntl(fd, F_SETFL, flags);

    return eaten;
}


static jmp_buf bye;

static void
zzz(int signo)
{
    longjmp(bye, signo);
}


static int
bouncespam(struct letter *let)
{
#if WITH_MILTER || defined(AV_PROGRAM)
    return (let->env->spam.action == spBOUNCE);
#else
    return 0;
#endif
}


static char*
bouncereason(struct letter *let)
{
    char *r = "Do you, my poppet, feel infirm?\n"
	      "I do believe you contain a germ";
	      
    if ( (let->env->spam.action == spBOUNCE) && let->env->spam.reason )
	return let->env->spam.reason;

    return r;
}


static void
sentence(struct letter *let, enum r_type term)
{
    int i;
/* reroute spam to a special quarantine area */

    for (i=0; i < let->local.count; i++)
	if (!isvhost(let->local.to[i].dom))
	    let->local.to[i].typ = term;
}


/* smtpbugcheck() - check the letter for spam (or other
 *                  milterish excuses) and return 1 if
 *                  it's okay, 0 if it's not. (exception:
 *                  if it's spam and the filter action is
 *                  to keep it, it sets a mailbox flag and
 *                  claims it's okay.  The actual delivery
 *                  agent will process according to the flag.
 */
static int
smtpbugcheck(struct letter *let)
{
#if WITH_MILTER
    char *what = 0;
    
    alarm(120);	/* allow 60 seconds to do all the bug checking */
    if ( let->healthy ) {
	int status = mfdata(let);
	if ( status == MF_OK )
	    return 1;
	else if ( status == MF_TEMP ) {
	    mfcomplain(let, "My brain hurts!");
	    return 0;
	}
    }
    
    if ( what = mfresult() ) {
	anotherheader(let, "X-Spam", what);
	syslog(LOG_ERR, "VIRUS from (%s,%s): %s",
			let->deliveredby, let->deliveredIP, what);
    }
    else {
	anotherheader(let, "X-Spam", "yes.  Lots of it.");
	syslog(LOG_ERR, "VIRUS from (%s,%s)",
			let->deliveredby, let->deliveredIP);
    }
    
    if (bouncespam(let)) {
	mfcomplain(let, bouncereason(let));
	return 0;
    }
	
    if (let->env->spam.action == spFILE)
	sentence(let, emSPAM);
    
    greylist(let, 1);
#else
    if ( virus_scan(let) != 0 ) {
	message(let->out, 550, "%s", bouncereason(let));
	return 0;
    }
#endif
    return 1;
}


static struct address *
parse_address(struct letter *let, char *p, int to)
{
    int reason;
    struct address *ret;

    if ( (ret = verify(let,0,p,(to ? VF_USER : VF_USER|VF_FROM), &reason)) != 0)
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


typedef int (*mfcheck)(struct letter *, char *);


static int
mfchk(mfcheck mf, struct letter *let, char *arg, char *soft, char *hard)
{
    if ( let->healthy ) {
	int status = (*mf)(let, arg);

	if ( status == MF_TEMP ) {
	    mfcomplain(let, soft);
	    return 0;
	}
	else if ( status != MF_OK ) {
	    switch ( let->env->spam.action ) {
	    case spBOUNCE:  mfcomplain(let, hard);
			    let->healthy = 0;
			    return 0;
	    case spFILE:    let->healthy = 0;
			    break;
	    default:        /*to make clang STFU */ ;
	    }
	}
    }
    return 1;
}


static int
from(struct letter *let, char *line, int *delay)
{
    char *p;
    struct address *from;
    long left;

    if (let->from) {
	message(let->out, 501, "Too many cooks spoil the broth.");
	return 5;
    }

    p = skipspace(line+4);
    if ( strncasecmp(p, "FROM", 4) != 0 || *(p = skipspace(p+4)) != ':' ) {
	message(let->out, 501, "Badly formatted mail from: command.");
	return 5;
    }

    p = skipspace(p+1);

    if ( !mfchk(mffrom, let, p, "I'm sorry, your name was?", "Not Allowed") )
	return mfcode() / 100;

    if ( (from = parse_address(let, p, 0)) == 0)
	return 5;

    if ( from->local && let->env->verify_from
		     && !(isvhost(from->dom) || let->env->relay_ok) ) {
	message(let->out, 501, "You are not a local client.");
	freeaddress(from);
	return 5;
    }
    else if ( (from->user == 0) && let->env->nodaemon )
	return 2;
    else
	let->from = from;

    *delay = 0;
    if ( (let->env->relay_ok == 0) && (left = greylist(let, 0)) > 1 )
	*delay = left;

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
    struct address *a;
    int rc = 0;

    if (strncasecmp(p, "TO", 2) != 0 || *(p = skipspace(p+2)) != ':') {
	message(let->out, 501, "Badly formatted rcpt to: command.");
	return 0;
    }

#if WITH_MILTER
    /* at least one milter freezes if you give it TO addresses
     * before FROM addresses.
     */
    if ( !let->from ) {
#if 1
	/* say "yes", but ignore the command */
	return 1;
#else
	message(let->out, 501, "But who is it from?");
	return 0;
#endif
    }
#endif

    p = skipspace(p+1);

    if ( !mfchk(mfto,let,p,"I can't read this address", "Not Allowed") )
	return 0;

    if ( (a = parse_address(let, p, 1)) == 0) return 0;

    if (a->user == 0) {
	a->alias = strdup("MAILER-DAEMON");
	let->reject |= let->env->nodaemon;
    }

    if (a->local || let->env->relay_ok) {
	if ((rc = recipients(let, a)) < 0) {
	    message(let->out, 451, "System error.");
	    rc = 0;
	}
	else if (rc == 0)
	    message(let->out, 550, "Who?");
    }
    else
	message(let->out, 550, "You may not relay through this server.");

    freeaddress(a);
    return rc;
}


static int
data(struct letter *let)
{
    register c;
    register dot = 0;
    long size = 0;

    if (mkspool(let) == 0) {
	message(let->out, 452,
		"Cannot store message body. Try again later.");
	return 0;
    }

    message(let->out, 354, "Bring it on.");

    while ( 1 ) {
	alarm(let->env->timeout);
	c = fgetc(let->in);
	alarm(0);

	if ( c == EOF ) {
	    syslog(LOG_ERR, "EOF during DATA from %s", let->deliveredby);
	    message(let->out, 451, "Unexpected EOF?");
	    break;
	}

	if ( c == '\r' ) continue; /* silently ignore \r's */

	/* dot states: 0 == newline, 1 == first char dot, 2 == rest of line */
	if ( c == '\n' ) {
	    if ( dot == 1 ) {
		alarm(0);
		return examine(let);
	    }
	    dot = 0;
	}
	else if ( dot == 0 && c == '.' ) {
	    dot = 1;
	    continue;
	}
	else
	    dot = 2;
    
	if ( fputc(c, let->body) == EOF ) {
	    syslog(LOG_ERR, "spool write error: %m");
	    message(let->out, 452,
		    "Cannot store message body. Try again later.");
	    break;
	}
    }
    do_reset(let);
    return 0;
}


static int
post(struct letter *let)
{
    int ok, didmsg=0;

    if (svspool(let) == 0)
	return 0;

    ok = (runlocal(let) == let->local.count) && !let->fatal;

    if ( !ok ) {
	/* something went wrong.  Report it */
	char *ptr;
	size_t size;

	fseek(let->log, SEEK_END, 0);

	if (let->log && (ptr = mapfd(fileno(let->log), &size)) ) {
	    message(let->out, 554, "Local mail delivery failed:\n%.*s",
		    size, ptr);
	    munmap(ptr, size);
	    didmsg = 1;
	}
	if (!didmsg)
	    message(let->out, 554,
		    let->fatal ? "Catastrophic error delivering local mail!"
			       : "Local mail delivery failed!");

	if (let->fatal)
	    byebye(let, EX_OSERR);
    }

    do_reset(let);
    return ok;
}


static int
helo(struct letter *let, enum cmds cmd, char *line)
{
    int i;
    struct iplist list;
    char *p;

    if ( !mfchk(mfhelo,let,line, "Where's my toast?", "How ill-mannered") )
	return 0;

    let->helo = 1;
    if (let->env->checkhelo && !let->env->relay_ok) {

	if (p = strchr(line, '\n')) {
	    /* trim trailing spaces */
	    while (p > line && isspace(p[-1]) )
		--p;
	    *p = 0;
	}

	if (getIPa(p=skipspace(line+4), IP_NEW, &list) > 0) {
	    for (i=0; i < list.count; i++)
		if (islocalhost(let->env, &(list.a[i].addr))) {
		    audit(let, (cmd==HELO)?"HELO":"EHLO", line, 521);
		    message(let->out, 521, "Liar, liar, pants on fire!");
		    freeiplist(&list);
		    /*syslog(LOG_DEBUG, "freeiplist(%p)", list);*/
		    return 0;
		}
	    freeiplist(&list);
	}
    }
    return 1;
}


static void
describe(FILE *f, int code, struct recipient *to, char *key)
{
    switch (to->typ) {
    case emALIAS:
	/* should never happen */
	message(f,-code, "to: ?alias [%s %s] %s", to->fullname, to->host, key);
	break;
    case emDENY:
	message(f,-code, "to: DENY [%d] %d %d %s", to->fullname, to->uid, to->gid, key);
	break;
    case emSPAM:
	message(f,-code, "to: SPAM [%d] %d %d %s", to->fullname, to->uid, to->gid, key);
	break;
    case emFILE:
	message(f,-code, "to: file [%s] %d %d %s", to->fullname, to->uid, to->gid, key);
	break;
    case emEXE:
	message(f,-code, "to: prog <[%s]> %d %d %s", to->fullname, to->uid, to->gid, key);
	break;
    case emUSER:
	if (to->host)
	    message(f,-code, "to: user %s [%s] %s", to->fullname, to->host, key);
	else
	    message(f,-code, "to: user %s %s", username(to->dom,to->user), key);
	break;
    }
}


static void
about(struct letter *let, char *who, struct spam *what)
{
    switch (what->action) {
    case spFILE:
	message(let->out, -250, "%s folder: <%s>", who,  what->folder);
	break;
    case spACCEPT:
	 message(let->out, -250, "%s: accept", who);
	 break;
    default:
	message(let->out, -250, "%s: bounce", who);
	break;
    }
}


static void
debug(struct letter *let)
{
    int i;
    ENV *env = let->env;

    audit(let, "DEBU", "", 250);
    if (let->from)
	message(let->out,-250,"From:<%s> /%s/%s/local=%d/alias=%s/\n",
		    let->from->full,
		    username(let->from->dom,let->from->user),
		    let->from->domain,
		    let->from->local,
		    let->from->alias);

    for (i=let->local.count; i-- > 0; )
	describe(let->out, 250, &let->local.to[i], "local");

    for (i=let->remote.count; i-- > 0; )
	describe(let->out, 250, &let->remote.to[i], "remote" );

    if (let->env->immediate)
	message(let->out, -250, "Immediate\n");
    message(let->out,-250, "Version: <%s>\n", myversion);
    message(let->out,-250, "Host: <%s>\n", let->env->localhost);
    message(let->out,-250, "B1FF!!!!: T\n");
    message(let->out,-250, "Health: %s\n", let->healthy ? "Good"
							: "Pining for the fjords");
#if WITH_PAM
    message(let->out, -250, "PAM: T\n");
#endif
#if WITH_TCPWRAPPERS
#if ORC_LIBWRAPPERS
    message(let->out,-250, "Enhanced TCP-wrappers: T\n");
#else
    message(let->out,-250, "Basic TCP-wrappers: T\n");
#endif
#endif
#if WITH_GREYLIST
    if ( let->env->greylist_from )
	message(let->out,-250, "Greylist: from-address\n");
    else
	message(let->out,-250, "Greylist: IP\n");
#endif
#ifdef AV_PROGRAM
    message(let->out,-250, "AV program: <%s>\n", AV_PROGRAM);
#endif
#ifdef WITH_MILTER
    mflist(let->out,-250);
#endif
    {   struct usermap *um;

	for (um = env->usermap; um; um = um->next)
	    message(let->out, -250, "User map: <(%s)> to <(%s)>\n",
			um->pat, um->map);
    }

    for (i=env->trusted.count; i-- > 0; )
	message(let->out, -250, "Trusted IP: %s\n",
			    inet_ntoa(env->trusted.a[i].addr));


#if USE_PEER_FLAG
    message(let->out,-250, "Peer flag: T\n");
#endif
#if WITH_COAL
    message(let->out,-250, "Coal: T\n");
#endif
    if (env->largest)
	message(let->out,-250, "size: %ld", env->largest);
    if (env->minfree)
	message(let->out,-250, "minfree: %ld", env->minfree);
    
    if (env->submission_port)
	message(let->out,-250, "submission port: %d", env->submission_port);
    about(let, "spam", &(env->spam));
    about(let, "forbidden", &(env->rej));

    message(let->out, 250, "Timeout: %d\n"
		      "Delay: %d\n"
		      "Max clients: %d\n"
		      "Qreturn: %ld\n"
		      "Relay-ok: %s\n"
		      "Verify-from: %s\n"
		      "CheckHELO: %s\n"
		      "NoDaemon: %s\n"
		      "LocalMX: %s\n"
		      "Paranoid: %s\n"
		      "Safe: %s\n"
		      "MXpool: %s\n"
		      "Escape-from: %s",
			  env->timeout,
			  env->delay,
			  env->max_clients,
			  env->qreturn,
			  env->relay_ok ? "T" : "NIL",
			  env->verify_from ? "T" : "NIL",
			  env->checkhelo ? "T" : "NIL",
			  env->nodaemon ? "T" : "NIL",
			  env->localmx ? "T" : "NIL",
			  env->paranoid ? "T" : "NIL",
			  env->safe ? "T" : "NIL", 
			  env->mxpool ? "T" : "NIL", 
			  env->escape_from ? "T" : "NIL" );
}


static void
go_away(struct letter *letter, FILE* out, char* reason)
{
    goodness(letter,-10);
    audit(letter,"CONN","outlawed", 521);
    message(out, 521, "%s does not accept mail"
		      " from %s because %s.", letter->deliveredto, letter->deliveredby, reason);
    syslog(LOG_ERR, "REJECT: DENY (%s, %s) %s", letter->deliveredby, letter->deliveredIP, reason);
    byebye(letter,1);
}


void
smtp(FILE *in, FILE *out, struct sockaddr_in *peer, ENV *env)
{
    char line[520];	/* rfc821 says 512; better to be paranoid */
    struct letter letter;
    time_t tick = time(NULL);
    extern char *nameof(struct sockaddr_in*);
    enum cmds c;
    int ok = 1, donotaccept = 0;
    char * why = 0;
    int patience = 5;
    char *p;
    int i, delay = 0;
    int rc, score, traf = 0;
    int timeout = env->timeout;
#ifdef SMTP_AUTH
    int auth_ok = 0;
#else
#   define auth_ok 0
#endif

    closelog();
    openlog("smtpd", LOG_PID, LOG_MAIL);

    myname(env);

    if ( prepare(&letter, in, out, env) ) {
	letter.deliveredby = peer ? strdup(nameof(peer)) : "localhost";
	letter.deliveredIP = peer ? strdup(inet_ntoa(peer->sin_addr)) : "127.0.0.1";
	letter.deliveredto = env->localhost;

	if (peer)	/* see if this is a trusted host */
	    for (i=0; i < env->trusted.count; i++)
		if (peer->sin_addr.s_addr == env->trusted.a[i].addr.s_addr) {
		    env->relay_ok = 1;
		    env->paranoid = 0;
		    break;
		}

	if ( (rc = mfconnect(&letter)) != MF_OK ) {
	    syslog(LOG_ERR, "milter problems");
	    message(out, 421, "We are having problems here, please try"
			      "again later.");
	    audit(&letter, "CONN", "milter", 421);
	    byebye(&letter, 1);
	}
#ifdef WITH_TCPWRAPPERS
	/* the tcp wrappers header file doesn't use prototyped declarations,
	 * so I'll cheat and use the same code for both the standard and
	 * my enhanced hosts_ctl calls
	 */
	if (!hosts_ctl("smtp", letter.deliveredby,
			       letter.deliveredIP, STRING_UNKNOWN, &why)) {
	    int status;

#if ORC_LIBWRAPPERS
	    if ( why ) {
		if ( strncmp("DENY=", why, 5) == 0 ) {
		    go_away(&letter, out, 5+why);
		    /* never returns, but free why to keep
		     * the sanity checker from flipping out */
		    free(why);
		}
	    }
	    else
		why = strdup("WHY=We get too much spam from your domain");
#else
	    if ( why = getenv("DENY") )
		go_away(&letter, out, why);
		/* never returns */

	    if ( (why = getenv("WHY")) == NULL )
		why="WHY=We get too much spam from your domain";
#endif

	    if ( env->rej.action == spBOUNCE ) {
		status=421;
		goodness(&letter, -10);
		audit(&letter, "CONN", "forbidden", 421);
		ok = 0;
		/*byebye(&letter, 1);*/
	    }
	    else {
		status=220;
		goodness(&letter, -5);
		donotaccept = 1;
	    }
#if ORC_LIBWRAPPERS
	    if ( p = strchr(why, '=') ) /* if the reason is in CODE=description form, just tell the caller the description */
		++p;
	    else
		p = why;
#endif

	    message(out, status, "%s does not accept mail"
			      " from %s because %s.", letter.deliveredto,
			      letter.deliveredby, p);
	    syslog(LOG_ERR, "REJECT: SPAM (%s, %s) %s",
				letter.deliveredby, letter.deliveredIP, p);
#if ORC_TCPWRAPPERS
	    free(why);
#endif
	}
	else
#endif
	if (env->paranoid && !strcmp(letter.deliveredby,letter.deliveredIP)) {
	    if ( env->rej.action == spBOUNCE ) {
		message(out, 421, "%s is not accepting mail from %s,"
				 " because we cannot resolve your IP address."
				 " Correct this, then try again later, okay?",
				 letter.deliveredto, letter.deliveredby);
		goodness(&letter, -10);
		audit(&letter, "CONN", "stranger", 421);
		byebye(&letter, 1);
	    }
	    else {
		goodness(&letter, -5);
		message(out, 220, "Hello, site with broken dns.");
		donotaccept = 1;
		audit(&letter, "CONN", "stranger", 220);
	    }
	    syslog(LOG_ERR, "REJECT: NO DNS (%s)", letter.deliveredIP);
	}
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
	message(letter.out, 421, "We'd love to talk to you but "
				 "our disk is on fire.");
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
    signal(SIGTSTP, zzz);
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

#if 0
	if (donotaccept) {
	    alarm(0);
	    sleep(15);
	}
#endif
	psstat(&letter, (c = cmd(line)) == MISC ? "ERR!" : line);

	alarm(60);	/* allow 60 seconds to process a command */
	if (ok) {
	    switch (c) {
	    case EHLO:
		if (ok = helo(&letter, c, line)) {
		    message(out,-250, "Hello, Sailor!");
		    if (env->largest)
			message(out,-250, "size %ld", env->largest);
#if SMTP_AUTH
		    message(out,-250, "auth login\n"
				      "auth=login");
#endif
		    message(out, 250, "no-soliciting\n"
		                      "8bitmime");
		    audit(&letter, "EHLO", line, 250);
		}
		else
		    score -= 4;
		break;

	    case HELO:
		if (ok = helo(&letter, c, line)) {
		    message(out, 250, "A wink is as good as a nod.");
		    audit(&letter, "HELO", line, 250);
		}
		else
		    score -= 4;
		break;
	    
	    case MAIL:
		traf++;
		if (letter.from)	/* rfc821 */
		    do_reset(&letter);

		if ( (rc = from(&letter, line, &delay)) == 2 ) {
		    audit(&letter, "MAIL", line, 250);
		    message(out, 250, "Okay fine.");
		    timeout = env->timeout;
		    score += 1;
		}
		else {
		    /* After a MAIL FROM:<> fails, put the
		     * caller on a really short input timer
		     * in case their tiny brain has popped
		     * as the result of getting a non 2xx
		     * reply
		     */
		    score -= 2;
		    audit(&letter, "MAIL", line, rc);
		    timeout = env->timeout / 10;
		}
		break;

	    case RCPT:
		traf++;
		if (to(&letter, line)) {
		    score += 1;
		    message(out, 250, "Sure, I love spam!");
		    audit(&letter, "RCPT", line, 250);
		}
		else {
		    score -= 2;
		    audit(&letter, "RCPT", line, 5);
		}
		break;

	    case DATA:
		if (letter.from && (letter.local.count || letter.remote.count) ) {
		    traf++;

		    if (letter.reject) {
			audit(&letter, "DATA", "reject", 501);
			message(out, 501, "Not Allowed.");
			score -= 2;
		    }
		    else if ( (auth_ok == 0) && (delay > 0) ) {
			char buf[40];
#if 0
# define GREYCODE 451
#else
# define GREYCODE 421
#endif

			if ( delay == INT_MAX ) {
			    audit(&letter, "DATA", "prohibited", GREYCODE);
			    message(out, GREYCODE, "System busy.  Try again later");
			}
			else {
			    sprintf(buf,"delay %d", delay);
			    audit(&letter, "DATA", buf, GREYCODE);
			    message(out, GREYCODE,
					"System busy.  Try again in %d second%s.",
					 delay, (delay==1) ? "" : "s");
			}
#if GREYCODE == 421
			audit(&letter, "QUIT", "greylist", 421);
			byebye(&letter,1);
#endif
		    }
		    else if ( data(&letter) ) {
			if (env->largest && (letter.bodysize > env->largest)) {
			    audit(&letter, "DATA", "size", 552);
			    message(out, 552, "I don't accept messages longer "
					    "than %lu bytes.", env->largest);
			}
			else if (letter.hopcount > env->max_hops) {
			    audit(&letter, "DATA", "looping", 554);
			    message(out, 554, "Too many Received: fields in "
					      "the message header.  Is it "
					      "looping?");
			}
			else {
			    alarm(0);
			    if ( donotaccept ) {
				if ( why )
				    anotherheader(&letter, "X-Spam",(char*)why);
				if ( env->rej.action == spFILE )
				    sentence(&letter, emDENY);
			    }
			    if ( ( (env->safe && auth_ok) || smtpbugcheck(&letter)) && post(&letter) ) {
				audit(&letter, "DATA", "", 250);
				message(out, 250, "Okay fine."); 
				score += 2;
			    }
			    else {
				score -= 1;
				audit(&letter, "DATA", "", 5);
			    }
			}
		    }
		    do_reset(&letter);
		}
		else {
		    purge(fileno(letter.in));
		    audit(&letter, "DATA", "", 503);
		    message(out, 503, "Who is it %s?", letter.from ? "TO" : "FROM");
		    score -= 2;
		}
		break;

	    case VRFY:
	    case EXPN:
		audit(&letter, line, "", (c==VRFY)?250:502);
		message(out, (c==VRFY)?250:502, "What's your clearance, Citizen?");
		break;

	    case RSET:
		audit(&letter, "RSET", "", 250);
		do_reset(&letter);
		message(out, 250, "Deja vu!");
		break;

	    case QUIT:
		mfquit(&letter);
		audit(&letter, "QUIT", "", 221);
		if (!traf)
		    goodness(&letter, -1);
		message(out, 221, "Be seeing you.");
		byebye(&letter, 0);

	    case NOOP:
		audit(&letter, "NOOP", "", 250);
		message(out, 250, "Yes, yes, I know you're busy.");
		break;
	    
#if SMTP_AUTH
	    case AUTH:
		if ( auth(&letter, line) ) {
		    auth_ok = 1;
		    env->relay_ok = 1;
		    donotaccept = 0;
		}
		else
		    goodness(&letter, -1);
		break;
#endif

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
		audit(&letter, line, line, 502);
		if (--patience < 1) {
		    byebye(&letter, 0);
		}
		else {
		    sleep(30);
		    message(out, 502, why ? "Sorry, but %s."
					  : "That would be a no.", why);
		}
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
