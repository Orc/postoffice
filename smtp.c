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

#ifdef WITH_TCPWRAPPERS
#include <tcpd.h>

int deny_severity = 0;
int allow_severity = 0;
#endif

#include "letter.h"
#include "smtp.h"
#include "env.h"

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


jmp_buf bye;

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
    int rc;
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
	    audit(&letter, "CONN", "blacklist", 554);
	    syslog(LOG_ERR, "REJECT: blacklist (%s, %s)",
				letter.deliveredby, letter.deliveredIP);
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
	alarm(timeout);
	psstat(&letter, "gets");
	if (fgets(line, sizeof line, in) == 0)
	    break;

	psstat(&letter, (c = cmd(line)) == MISC ? "ERR!" : line);

	alarm(60);	/* allow 60 seconds to process a command */
	if (ok) {
	    switch (c) {
	    case EHLO:
		greeted(&letter);
		message(out,-250, "Hello, Sailor!");
		if (env->largest)
		    message(out,-250, "size %ld", env->largest);
		message(out, 250, "8bitmime");
		audit(&letter, "EHLO", line, 250);
		break;

	    case HELO:
		greeted(&letter);
		message(out, 250, "A wink is as good as a nod.");
		audit(&letter, "HELO", line, 250);
		break;
	    
	    case MAIL:
		if (letter.from)	/* rfc821 */
		    reset(&letter);

		if ( (rc = from(&letter, line)) == 2 ) {
		    audit(&letter, "MAIL", line, 250);
		    message(out, 250, "Okay fine.");
		    timeout = env->timeout;
		}
		else {
		    /* After a MAIL FROM:<> fails, but the
		     * caller on a really short input timer
		     * in case their tiny brain has popped
		     * as the result of getting a non 2xx
		     * reply
		     */
		    audit(&letter, "MAIL", line, rc);
		    timeout = env->timeout / 10;
		}
		break;

	    case RCPT:
		if (to(&letter, line)) {
		    message(out, 250, "Sure, I love spam!");
		    audit(&letter, "RCPT", line, 250);
		}
		else
		    audit(&letter, "RCPT", line, 5);
		break;

	    case DATA:
		if (letter.from && (letter.local.count || letter.remote.count) ) {
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
			    }
			    else
				audit(&letter, "DATA", "", 5);
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
		message(out, 221, "Be seeing you.");
		byebye(&letter, 0);

	    case NOOP:
		audit(&letter, "NOOP", "", 250);
		message(out, 250, "Yes, yes, I know you're busy.");
		break;
	    
	    case DEBU:
		if (env->debug) {
		    int i;

		    audit(&letter, "DEBU", "", 250);
		    if (letter.from)
			message(out,-250,"From:<%s> /%s/%s/local=%d/alias=%s/",
				    letter.from->full,
				    letter.from->user,
				    letter.from->domain,
				    letter.from->local,
				    letter.from->alias);

		    for (i=letter.local.count; i-- > 0; )
			describe(out, 250, &letter.local.to[i] );

		    for (i=letter.remote.count; i-- > 0; )
			describe(out, 250, &letter.remote.to[i] );

		    message(out,-250, "B1FF!!!!: T\n");
#ifdef WITH_TCPWRAPPERS
		    message(out,-250, "Tcp-Wrappers: T\n");
#endif
#ifdef WITH_GREYLIST
		    message(out,-250, "Greylist: T\n");
#endif
#ifdef AV_PROGRAM
		    message(out,-250, "AV program: <%s>\n", AV_PROGRAM);
#endif
#ifdef USE_PEER_FLAG
		    message(out,-250, "Peer flag: T\n");
#endif
		    if (env->largest)
			message(out,-250, "size: %ld", env->largest);
		    message(out, 250, "Timeout: %d\n"
				      "Delay: %d\n"
				      "Max clients: %d\n"
				      "Qreturn: %ld\n"
				      "Relay-ok: %s\n"
				      "NoDaemon: %s\n"
				      "LocalMX: %s\n"
				      "Paranoid: %s",
					  env->timeout,
					  env->delay,
					  env->max_clients,
					  env->qreturn,
					  env->relay_ok ? "T" : "NIL",
					  env->nodaemon ? "T" : "NIL",
					  env->localmx ? "T" : "NIL",
					  env->paranoid ? "T" : "NIL" );
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
	    sleep(30);
	    if (c == QUIT) {
		audit(&letter, "QUIT", "", 221);
		message(out,221,"Be seeing you.");
		byebye(&letter, 0);
	    }
	    else {
		audit(&letter, line, line, 503);
		message(out,503,"I'm sorry Dave, I'm afraid I can't do that.");
	    }
	}
	fflush(out);
	fflush(in);
    } while ( !(feof(out) || feof(in)) );
    audit(&letter, "QUIT", "EOF", 421);
    byebye(&letter,1);
}
