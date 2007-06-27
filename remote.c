#include "config.h"

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <syslog.h>
#include <setjmp.h>
#include <signal.h>

#include "letter.h"
#include "mbox.h"
#include "bounce.h"
#include "socklib.h"

static enum r_status
             /*  EOF      1dd     2dd      3dd      4dd     5dd   */
statii[10] = { PENDING, PENDING, ACCEPTED, PENDING, PENDING, REFUSED };

static int
SMTPwrite(MBOX *f, char *text, unsigned long size)
{
    register c = 0;
    register x = 0;
    void (*oldalarm)(int);
    int ret;

    oldalarm = signal(SIGALRM, timer_expired);

    if (setjmp(timer_jmp) == 0) {
	alarm(900);	/* give 15 minutes to mail the message body */
	for ( ; (size-- > 0) && !ferror(f->out); x++, text++ ) {
	    c = *text;
	    if ( (c == '.') && (x == 0 || text[-1] == '\n') )
		fputc('.', f->out);
	    else if (c == '\n')
		fputc('\r', f->out);
	    fputc(c, f->out);
	}
	fflush(f->out);
	alarm(0);
	ret = !ferror(f->out);
    }
    else {
	syslog(LOG_INFO, "%s teergrube", inet_ntoa(f->ip));
	ret = 0;
    }

    signal(SIGALRM, oldalarm);
    return ret;
}


static int
SMTPpost(MBOX *session, struct letter *let, int first, int last)
{
    enum r_status status;
    int ok, accepted=0, code;
    int i;
    int denied = 0;
    off_t base = 0;
    int slowpoke = 0;

    rewind(session->log);

    writembox(session, session->sizeok ? "MAIL FROM:<%s> SIZE=%ld"
				       : "MAIL FROM:<%s>",
		      let->from ? let->from->full : "",
		      (long)(let->bodysize * 1.25));

    switch (code = reply(session,0)) {
    case 2:	break;
    case 5:	/* refused mail from this address */
		for (i=first; i < last; i++)
		    let->remote.to[i].status = REFUSED;
		return 1;
    case 0:	/* hangup */
		if (session->verbose)
		    fprintf(stderr, "*Hangup*\n");
		fprintf(session->log, "\tLost connection to server\n");
    default:
		for (i=first;i < last; i++)
		    let->remote.to[i].status = PENDING;
		return 0;
    }
    fseek(session->log, base, SEEK_SET);

    for (i = first; i < last; i++) {
	fprintf(session->log, "To <%s><%s>: ",
				let->remote.to[i].fullname,
				let->remote.to[i].host);
	writembox(session, "RCPT TO:<%s>", let->remote.to[i].fullname);

	switch ( code = reply(session, 0) ) {
	case 2:	let->remote.to[i].status = ACCEPTED;
		accepted++;
		break;
	case 4: let->remote.to[i].status = PENDING;
		break;
	case 5: let->remote.to[i].status = REFUSED;
		denied++;
		base = ftell(session->log);
		syslog(LOG_INFO,
			"delivery failed from %s (qid %s) to %s (%s)",
			let->from ? let->from->full : "MAILER-DAEMON",
			let->qid,
			let->remote.to[i].fullname,
			let->remote.to[i].host);
		break;
	case 0: /* disconnect */
		if (session->verbose)
		    fprintf(stderr, "*Hangup*\n");
		fprintf(session->log, "\tLost connection to server\n");
		return denied;
	default:fseek(session->log, base, SEEK_SET);
		break;
	}
    }

    if (!accepted) {
	/* none of our RCPT TO:'s were accepted */
	return denied;
    }

    fseek(session->log, base, SEEK_SET);

    fprintf(session->log, "DATA\n");
    writembox(session, "DATA");


    switch (code = reply(session, 0)) {
    case 5:	/* client refused the DATA command; set all ACCEPTED
		 * recipients back to PENDING and try again later
		 */
	for (i=first; i < last; i++)
	    if (let->remote.to[i].status == ACCEPTED)
		let->remote.to[i].status = PENDING;
	return denied;

    case 3:
	if (let->headtext) {
	    ok = SMTPwrite(session, let->headtext, let->headsize);

	    if (ok && !let->has_headers)
		ok = SMTPwrite(session, "\n", 1);
	}
	else
	    ok = 1;

	ok = ok && SMTPwrite(session, let->bodytext, let->bodysize);
	if (let->bodysize > 0 && let->bodytext[let->bodysize-1] != '\n')
	    ok = ok && SMTPwrite(session, "\n", 1);

	if (ok) {
	    writembox(session, ".");
	    code = reply(session, 0);

	    switch (code) {
	    case 2:
		fseek(session->log, base, SEEK_SET);

		for (i=first; i<last;i ++)
		    if (let->remote.to[i].status == ACCEPTED) {
			let->remote.to[i].status = MAILED;
			syslog(LOG_INFO,
				"deliver mail from %s (qid %s) to %s (%s)",
				let->from ? let->from->full : "MAILER-DAEMON",
				let->qid,
				let->remote.to[i].fullname,
				let->remote.to[i].host);
		    }
		return denied;
	    case 5:
		/* message body not accepted */
		for (i=first; i < last; i++)
		    if (let->remote.to[i].status == ACCEPTED)
			let->remote.to[i].status = REFUSED;
		return 1;
	    /* else fall through into default */
	    }
	}
	/* else fall through into default */
    }

    /* default;  if we get here, put all recipients back to pending,
     * log an error in the session log, and fail
     */
    for (i=first; i<last; i++)
	if (let->remote.to[i].status == ACCEPTED)
	    let->remote.to[i].status = PENDING;
    fprintf(session->log, "\tError sending mail: %s\n", strerror(errno));
    return denied;
}


static void
send_to_remote(struct letter *let, char *host, int i, int j)
{
    MBOX *f;
    char *logtext;
    long logsize;
    size_t mapsize;
    int rc;

    if (f = session(let->env, host, 25)) {
	if ( SMTPpost(f, let, i, j) > 0 ) {
	    logsize = ftell(f->log);
	    fflush(f->log);
	    if (logtext = mapfd(fileno(f->log), &mapsize)) {
		bounce(let, logtext, logsize, REFUSED);
		munmap(logtext, mapsize);
	    }
	    else
		bounce(let, "\tCatastrophic system error", -1, REFUSED);

#if 0
	    if (rc < 0)
		dump_session(f);
#endif
	}
	writecontrolfile(let);
    }
}


#define Samehost(i,j)	(!strcasecmp(let->remote.to[i].host,let->remote.to[j].host))


forward(struct letter *let)
{
    unsigned int i, j;

    for (i=0; i < let->remote.count; i++)
	let->remote.to[i].status = PENDING;

    if (let->env->relay_host)
	send_to_remote(let, let->env->relay_host, 0, let->remote.count);
    else {
	for (i=0; i < let->remote.count; i = j) {
	    for (j=i+1; (j < let->remote.count) && Samehost(i,j); ++j)
		;
	    send_to_remote(let, let->remote.to[i].host, i, j);
	}
    }
}
