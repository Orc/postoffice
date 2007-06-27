#include "config.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <string.h>
#include <syslog.h>
#include <sysexits.h>
#include <signal.h>
#include <stdarg.h>
#include <errno.h>

#if OS_FREEBSD
#   include <stdlib.h>
#else
#   include <malloc.h>
#endif

#include "letter.h"
#include "env.h"

static void
say(char *fmt, ...)
{
    va_list ptr;

    va_start(ptr,fmt);
    vsyslog(LOG_ERR, fmt, ptr);
    va_end(ptr);

    va_start(ptr,fmt);
    vfprintf(stderr, fmt, ptr);
    fputc('\n', stderr);
    fflush(stderr);
    va_end(ptr);
}


static void
mailbugcheck(struct letter *let)
{
    int code = virus_scan(let);
    register c;

    if (code != 0) {
	if (let->log != stderr) {
	    rewind(let->log);
	    while ( (c = fgetc(let->log)) != EOF)
		putchar(c);
	}
	byebye(let, (code/100 == 4) ? EX_OSERR : EX_UNAVAILABLE);
    }
}


int
addto(struct letter *let, char *who)
{
    struct address *addr;
    int ret;

    if ( (*who == 0) || ((addr = verify(let, who, VF_USER, 0)) == 0) )
	return 0;

    ret = recipients(let, addr);
    freeaddress(addr);

    return ret;
}


static char*
isto(char *line)
{
    if (strncasecmp(line, "TO:", 3) == 0)
	return line+3;
    else if (strncasecmp(line, "CC:", 3) == 0)
	return line+3;
    else if (strncasecmp(line, "BCC:", 4) == 0)
	return line+4;
    return 0;
}


static int
collect(struct letter *let)
{
    register c;
    enum { F, B } state;
    char *p, *q;
    int rc;
    extern char *arpatok(char **);

    if (let->env->trawl) { /* need to read in headers */
	int size, len;
	char *line = malloc(size=2000);

	if (line == 0) {
	    syslog(LOG_ERR, "collect: %m");
	    return 0;
	}
	/* read in the headers, buffering up into lines.  If we find
	 * an empty line or a line that isn't a header, we're done and
	 * can revert to the regular sort of collection.
	 */
	for (state=F, len=0; (c = fgetc(let->in)) != EOF; line[len++] = c) {
	    if (state == F) {
		if (c == ':')
		    state = B;
		else if ( !(isalnum(c) || c == '-' || c == '_') ) {
		    line[len++] = c;
		    break;		/* not a header anymore */
		}
	    }
	    else if (c == '\n') {
		line[len++] = c;
		line[len] = 0;

		if ( (c = fgetc(let->in)) == EOF)
		    break;
		else if (c == ' ' || c == '\t')	/* header continuation line */
		    ;
		else {
		    /* process this header line */
		    if (p = isto(line)) {
			if (strncasecmp(line, "Bcc:", 4) != 0)
			    fwrite(line, len, 1, let->body);

			while (q = arpatok(&p)) {
			    if (strlen(q) == 0)
				continue;
			    else if ( (rc = addto(let, q)) == 0 )
				say("cannot mail to %s", q);
			    else if (rc < 0)
				return 0;
			}
		    }
		    else
			fwrite(line, len, 1, let->body);

		    len = 0;
		    state = F;
		}
	    }
	    else if ( (len > size-10) && !(line = realloc(line, size += 1000)) )
		return 0;
	}
	if (ferror(let->body))
	    return 0;
	if (len > 0)
	    fwrite(line, 1, len, let->body);
	free(line);

	if (c == EOF)
	    return examine(let);
    }


    while ( (c = fgetc(let->in)) != EOF ) {
	if (fputc(c,let->body) == EOF) {
	    syslog(LOG_ERR, "spool write error: %m");
	    return 0;
	}
    }
    return examine(let);
}


static void
catchsig(int sig)
{
    say("Caught signal %d", sig);
}



int
mail(char *from, int argc, char **argv, ENV *env)
{
    struct letter let;
    char *ptr;
    int reason;
    int count;
    int total = 0;
    int rc;


    if (from == 0) {
	struct passwd *pwd = getpwuid(env->sender);

	from = pwd ? strdup(pwd->pw_name) : "nobody";
    }

    /*syslog(LOG_INFO, "mail: begin");*/
    if ( prepare(&let, stdin, stdout, env) == 0 ) {
	say("mail init: %s", strerror(errno));
	byebye(&let, EX_OSERR);
    }
    /*syslog(LOG_INFO, "mail: prepare");*/
    let.deliveredto = let.deliveredby = env->localhost;
    let.deliveredIP = "127.0.0.1";	/* woe is us if IPv6 wins */

    if ( (let.from = verify(&let, from, VF_USER|VF_FROM, &reason)) == 0) {
	say("Unknown sender <%s>", from);
	byebye(&let, EX_NOUSER);
    }
    /*syslog(LOG_INFO, "mail: verify");*/

    if ( !env->trawl ) {
	if (argc <= 0) {
	    say("No recipients");
	    byebye(&let, EX_NOUSER);
	}
	for ( ;argc-- > 0; ++argv)
	    if ( (count = addto(&let, *argv)) < 0)
		byebye(&let, EX_OSERR);
	    else if (count == 0)
		say("Ignoring unknown recipient <%s>", *argv);
	    else
		total += count;

	if (total == 0)
	    byebye(&let, EX_NOUSER);
    }
    /*syslog(LOG_INFO, "mail: trawl");*/

    if (mkspool(&let) == 0 || collect(&let) == 0) {
	say("collecting message body: %s", strerror(errno));
	byebye(&let, EX_OSERR);
    }
    /*syslog(LOG_INFO, "mail: mkspool");*/

    signal(SIGALRM, SIG_IGN);
    signal(SIGALRM, SIG_IGN);

    signal(SIGQUIT, catchsig);
    signal(SIGKILL, catchsig);
    signal(SIGTERM, catchsig);
    signal(SIGILL,  catchsig);
    signal(SIGINT,  catchsig);
    signal(SIGBUS,  catchsig);
    /*syslog(LOG_INFO, "mail: signaled");*/

    if (let.local.count == 0 && let.remote.count == 0) {
	say("No recipients");
	byebye(&let, EX_NOUSER);
    }

    mailbugcheck(&let);
    /*syslog(LOG_INFO, "mail: bugcheck");*/

    if (svspool(&let) == 0) {
	say("storing message body: %s", strerror);
	byebye(&let, EX_OSERR);
    }
    /*syslog(LOG_INFO, "mail: svspool");*/

    rc = runlocal(&let);
    /*syslog(LOG_INFO, "mail: runlocal");*/

    if (let.fatal || (rc < let.local.count) ) {
	char *ptr;
	size_t size;

	/* something went wrong.  Report it */
	if (let.log) {
	    rewind(let.log);

	    if ( ptr = mapfd(fileno(let.log), &size) ) {
		syslog(LOG_ERR, "Local mail delivery failed");
		fprintf(stderr, "Local mail delivery failed:\n%.*s", size, ptr);
		munmap(ptr, size);
	    }
	    byebye(&let, let.fatal ? EX_OSERR : EX_SOFTWARE );
	}
	say(let.fatal ? "Catastrophic error delivering local mail!"
		      : "Local mail delivery failed!");

	byebye(&let, let.fatal ? EX_OSERR : EX_SOFTWARE );
    }
    /*syslog(LOG_INFO, "mail: fini");*/
    byebye(&let, EX_OK);
}
