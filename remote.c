#include "config.h"

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <syslog.h>

#include "letter.h"
#include "mbox.h"
#include "bounce.h"

static enum r_status
             /*  EOF      1dd     2dd      3dd      4dd     5dd   */
statii[10] = { PENDING, PENDING, MAILED, PENDING, PENDING, FAILED };

static int
SMTPwrite(MBOX *f, char *text, unsigned long size)
{
    register c = 0;
    register x = 0;

    for ( ; (size-- > 0) && !ferror(f->out); x++, text++ ) {
	c = *text;
	if ( (c == '.') && (x == 0 || text[-1] == '\n') )
	    fputc('.', f->out);
	else if (c == '\n')
	    fputc('\r', f->out);
	fputc(c, f->out);
    }
    if (c != '\n')
	fputs("\r\n", f->out);

    fflush(f->out);
    return !ferror(f->out);
}


static int
SMTPpost(MBOX *session, struct letter *let, int first, int last, int *denied)
{
    enum r_status status;
    int ok=0, code;
    int i;
    off_t base = 0;

    *denied = 0;
    rewind(session->log);

    writembox(session, session->esmtp ? "MAIL FROM:<%s> SIZE=%ld"
			              : "MAIL FROM:<%s>",
		      let->from->full, (long)(let->bodysize * 1.25));

    if ( (status = statii[code = reply(session, 0)]) != MAILED) {
	for (i=first; i < last; i++)
	    let->remote.to[i].status = status;
	if (status == FAILED)
	    *denied = last-first;
	if (code == 0)
	    fprintf(session->log, "\tLost connection to server\n");
	return -1;
    }
    fseek(session->log, base, SEEK_SET);

    for (i = first; i < last; i++) {
	fprintf(session->log, "To <%s><%s>: ",
				let->remote.to[i].fullname,
				let->remote.to[i].host);
	writembox(session, "RCPT TO:<%s>", let->remote.to[i].fullname);

	if ( (code = reply(session,0)) == 0) {
	    fprintf(session->log, "\tLost connection to server\n");
	    return 0;	/* client hung up */
	}
	switch (let->remote.to[i].status = statii[code]) {
	case MAILED:ok++;
	default:    fseek(session->log, base, SEEK_SET);
		    break;
	case FAILED:base = ftell(session->log);
		    (*denied)++;
		    syslog(LOG_INFO,
			    "delivery failed from %s (qid %s) to %s (%s)",
			    let->from->full,
			    let->qid,
			    let->remote.to[i].fullname,
			    let->remote.to[i].host);
		    break;
	}
    }

    if (!ok) {
	/* none of our RCPT TO:'s were accepted */
	return 0;
    }

    fseek(session->log, base, SEEK_SET);

    fprintf(session->log, "DATA\n");
    writembox(session, "DATA");
    code = reply(session, 0);

    if (code == 3) {
	if (let->headtext) {
	    ok = SMTPwrite(session, let->headtext, let->headsize);

	    if (ok && !let->has_headers)
		ok = SMTPwrite(session, "\n", 1);
	}
	else
	    ok = 1;

	ok = ok && SMTPwrite(session, let->bodytext, let->bodysize);

	if (ok) {
	    writembox(session, ".");
	    code = reply(session, 0);

	    if (code == 2) {
		fseek(session->log, base, SEEK_SET);

		for (i=first; i<last;i ++)
		    if (let->remote.to[i].status == MAILED)
			syslog(LOG_INFO,
				"deliver mail from %s (qid %s) to %s (%s)",
				let->from->full,
				let->qid,
				let->remote.to[i].fullname,
				let->remote.to[i].host);
		return 1;
	    }
	}
	fprintf(session->log, "\tError sending mail: %s\n", strerror(errno));
    }
    /* if we got a 2dd status back, that just doesn't make sense,
     * so just defer the message until later.
     */
    status = statii[ (code==2) ? 4 : code ];

    /* reset all output to PENDING */
    for (i=first; i < last; i++)
	let->remote.to[i].status = status;

    if (status == FAILED)
	*denied = last-first;

    return 0;
}

#define Samehost(i,j)	(!strcmp(let->remote.to[i].host,let->remote.to[j].host))


forward(struct letter *let)
{
    unsigned int i, j;
    MBOX *f;
    unsigned int denied;
    char *logtext;
    long logsize;
    size_t mapsize;
    int rc;

    for (i=0; i < let->remote.count; i = j) {

	for (j=i+1; j < let->remote.count && (j-i) < 100 && Samehost(i,j); ++j)
	    let->remote.to[i].status = PENDING;

	if (f = session(let->env, let->remote.to[i].host, 25)) {
	    if ( (rc = SMTPpost(f, let, i, j, &denied)) < 0 || denied > 0 ) {
		logsize = ftell(f->log);
		fflush(f->log);
		if (logtext = mapfd(fileno(f->log), &mapsize)) {
		    bounce(let, logtext, logsize, FAILED);
		    munmap(logtext, mapsize);
		}
		else
		    bounce(let, "\tCatastrophic system error", -1, FAILED);

		if (rc < 0)
		    dump_session(f);
	    }
	}
    }
}
