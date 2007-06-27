#include "config.h"

#include <stdio.h>
#include <syslog.h>
#include <string.h>

#include "letter.h"
#include "mbox.h"
#include "bounce.h"

void
bounce(struct letter *let, char *logtext, long logsize, enum r_status code)
{
    struct letter bounce;
    struct address *postmaster;
    int st;
    FILE *bf;
    static char boundary[] = "OH,NO!";
    char *ptr, *eptr;
    int i;
    int comma = 0;
    int picky = 0;

    prepare(&bounce, 0, 0, let->env);

    bounce.deliveredby=let->env->localhost;
    bounce.deliveredIP=let->env->localhost;
    bounce.mesgfrom=1;
    bounce.has_headers=1;

    if (logtext && (logsize == -1))
	logsize = strlen(logtext);

    if (let->from->user == 0 || strlen(let->from->user) == 0) {
	/* can't bounce to <>; drop it on the floor?  Send it to
	 * the local postmaster?
	 */
	st = 0;
    }
    else
	st = recipients(&bounce, let->from);

    if (st <= 0) {
	int ok;
	ok = (postmaster = verify(&bounce, "postmaster", 1, &st)) &&
			       (recipients(&bounce, postmaster) > 0);
	if (postmaster)
	    freeaddress(postmaster);

	if ( !ok ) {
	    syslog(LOG_ERR, "double-bounce: no postmaster?");
	    reset(&bounce);
	    return;
	}
    }
    if ( bounce.from = mkaddress("") ) {
	if (mkspool(&bounce)) {
	    fprintf(bounce.body, "Subject: Undeliverable mail\n"
				 "From: Mail system on %s <MAILER-DAEMON>\n"
				 "MIME-Version: 1.0\n"
				 "Content-Type: multipart/report;\n"
				 "              report-type=delivery-status;\n"
				 "              boundary=\"%s\"\n"
				 "\n"
				 "--%s\n", let->env->localhost,
					     boundary, boundary);
	    fprintf(bounce.body, "\nThe mail service at %s was unable to \n"
				 "deliver your mail to\n",
				    let->env->localhost);

	    picky = logtext && (strncmp(logtext, "To <", 4) == 0);

	    for (i=0; i < let->remote.count; i++)
		if (let->remote.to[i].status == code)
		    fprintf(bounce.body, "\t%s\n", let->remote.to[i].fullname);
	    fputc('\n', bounce.body);
	    if (logtext && !picky) {
		fprintf(bounce.body, "\n\n-%s\n"
				     "content-type: text/plain\n"
				     "content-description: mail log\n"
				     "\n", boundary);
		fwrite(logtext, logsize, 1, bounce.body);
	    }

	    fprintf(bounce.body, "\n\n--%s\n"
				 "content-type: message/delivery-status\n"
				 "content-description: delivery status\n"
				 "\n"
				 "Reporting-MTA: dns; %s\n",
					 boundary, let->env->localhost);

	    if (picky) {
		for (ptr = logtext, eptr = logtext + logsize; ptr < eptr; ) {
		    ptr += 4;
		    fprintf(bounce.body, "\nOriginal-Recipient: rfc822;");
		    while ((ptr < eptr) && (*ptr != '>'))
			fputc(*ptr++, bounce.body);
		    if (strncmp(ptr, "><", 2) == 0) {
			ptr += 2;
			fprintf(bounce.body, "\nRemote-MTA: dns;");
			while ((ptr < eptr) && (*ptr != '>'))
			    fputc(*ptr++, bounce.body);
		    }
		    if (strncmp(ptr, ">: ", 3) == 0)
			ptr += 3;

		    fprintf(bounce.body, "\nAction: failed");
		    while ( (ptr < eptr) && (strncmp(ptr, "To <", 4) != 0) ) {
			fprintf(bounce.body, "\nDiagnostic-Code: smtp;");
			while (ptr < eptr && *ptr != '\n')
			    fputc(*ptr++, bounce.body);
			ptr++;
		    }
		    fputc('\n', bounce.body);
		}
	    }
	    else for (i=0; i < let->remote.count; i++) {
		if (let->remote.to[i].status == code)
		    fprintf(bounce.body, "\nOriginal-Recipient: rfc822;%s\n"
					 "Action: failed\n",
					 let->remote.to[i].fullname);
	    }

	    fprintf(bounce.body, "\n\n--%s--\n", boundary);

	    fflush(bounce.body);

	    if (bounce.bodytext = mapfd(fileno(bounce.body),&bounce.bodysize)) {
		runlocal(&bounce);
		svspool(&bounce);
	    }
	    else {
		syslog(LOG_ERR, "Could not mapfd() bounce message: %m");
		/* oops! */
	    }
	}
    }
    reset(&bounce);
}
