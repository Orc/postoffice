#include "config.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <string.h>
#include <syslog.h>
#include <sysexits.h>

#if OS_FREEBSD
#   include <stdlib.h>
#else
#   include <malloc.h>
#endif

#include "letter.h"
#include "env.h"

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


static int
addto(struct letter *let, char *who)
{
    struct address *addr;
    int ret;

    if ( (*who == 0) || ((addr = verify(let, who, 1, 0)) == 0) )
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

		if ( (c = fgetc(let->in)) == EOF)
		    break;
		else if (c == ' ' || c == '\t')	/* header continuation line */
		    ;
		else {
		    ungetc(c, let->in);
		    /* process this header line */
		    if (p = isto(line)) {
			if (strncasecmp(line, "Bcc:", 4) != 0)
			    fwrite(line, len, 1, let->body);

			line[len] = 0;
			while (q = arpatok(&p))
			    if ( (rc = addto(let, q)) == 0 )
				fprintf(stderr, "cannot mail to %s\n", q);
			    else if (rc < 0)
				return 0;
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

    superpowers();
    if ( prepare(&let, stdin, stdout, env) == 0 ) {
	perror("mail init");
	byebye(&let, EX_OSERR);
    }
    let.deliveredto = let.deliveredby = env->localhost;
    let.deliveredIP = "127.0.0.1";	/* woe is us if IPv6 wins */

    if ( (let.from = verify(&let, from, 1, &reason)) == 0) {
	fprintf(stderr, "Unknown sender <%s>\n", from);
	byebye(&let, EX_NOUSER);
    }

    if ( !env->trawl ) {
	if (argc <= 0) {
	    fprintf(stderr, "No recipients\n");
	    byebye(&let, EX_NOUSER);
	}
	for ( ;argc-- > 0; ++argv)
	    if ( (count = addto(&let, *argv)) < 0)
		byebye(&let, EX_OSERR);
	    else if (count == 0)
		fprintf(stderr, "Ignoring unknown recipient <%s>\n", *argv);
	    else
		total += count;

	if (total == 0)
	    byebye(&let, EX_NOUSER);
    }

    if (mkspool(&let) == 0 || collect(&let) == 0) {
	perror("collecting message body");
	byebye(&let, EX_OSERR);
    }

    if (let.local.count == 0 && let.remote.count == 0) {
	fprintf(stderr, "No recipients\n");
	byebye(&let, EX_NOUSER);
    }

    mailbugcheck(&let);

    if (svspool(&let) == 0) {
	perror("storing message body");
	byebye(&let, EX_OSERR);
    }

    rc = runlocal(&let);

    if (let.fatal || (rc < let.local.count) ) {
	char *ptr;
	size_t size;

	/* something went wrong.  Report it */
	if (let.log) {
	    rewind(let.log);

	    if ( ptr = mapfd(fileno(let.log), &size) ) {
		fprintf(stderr, "Local mail delivery failed:\n%.*s", size, ptr);
		munmap(ptr, size);
	    }
	    byebye(&let, let.fatal ? EX_OSERR : EX_SOFTWARE );
	}
	fprintf(stderr, let.fatal ? "Catastrophic error delivering local mail!"
				  : "Local mail delivery failed!");

	byebye(&let, let.fatal ? EX_OSERR : EX_SOFTWARE );
    }
    byebye(&let, EX_OK);
}
