#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <time.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <malloc.h>

#include "spool.h"

#include "letter.h"
#include "env.h"
#include "mx.h"


int
examine(struct letter *let)
{
#define ISHDR(p,f)	(strncasecmp(p,f,strlen(f)) == 0)
    char *p, *ep;
    int contin = 0;

    fflush(let->body);

    if ( (let->bodytext = mapfd(fileno(let->body), &let->bodysize)) == 0 ) {
	syslog(LOG_ERR, "cannot mmap() the email body: %m");
	return 0;
    }
    let->has_headers = 0;

    /* check the message for headers */
    for (p = let->bodytext, ep = p+let->bodysize ; p && (p < ep); ) {
	if (*p == ' ' || *p == '\t') {
	    if (contin)
		p = memchr(p, '\n', (ep-p));
	    else
		break;
	}
	else if (isalnum(*p)) {
	    if (ISHDR(p, "received:"))
		let->hopcount++;
	    else if (ISHDR(p, "date:"))
		let->date = 1;
	    else if (ISHDR(p, "message-id:"))
		let->messageid = 1;
	    else if (ISHDR(p, "from:"))
		let->mesgfrom = 1;

	    contin=1;
	    while ( (p < ep) && *p != ':' && *p != '\n')
		++p;

	    if (*p != ':')
		break;

	    let->has_headers = 1;
	    p = memchr(p, '\n', (ep-p));
	}
	else if (*p == '\n')
	    break;

	if (p) ++p;
    }
    return 1;
}


int
mkspool(struct letter *let)
{
    static char tempfile[sizeof(TEMPPFX)+20+1];
    int f;

    strcpy(tempfile, TEMPPFX "XXXXXX");

    umask(077);
    if ( (f = mkstemp(tempfile)) == -1 || (let->body = fdopen(f, "w+")) == 0) {
	if (f != -1) close(f);
	syslog(LOG_ERR, "%s: %m", tempfile);
	return 0;
    }
    let->tempfile = tempfile;
    return 1;
}



void
receivedby(FILE *f, struct letter *let, struct recipient *to)
{
    char date[80];
    int nullfrom = !(let->from->full && (strlen(let->from->full) > 0));

    if (!let->mboxfrom) {
	strftime(date, 80, "%a %b %d %H:%M:%S %Y", localtime(&let->posted));
	fprintf(f, "From %s %s\n", nullfrom ? "<>" : let->from->full, date);
    }

    strftime(date, 80, "%a, %d %b %Y %H:%M:%S %Z", localtime(&let->posted));
    if (strcmp(let->deliveredby, let->deliveredIP) != 0)
	fprintf(f, "Received: from %s (%s)\n", let->deliveredby,
					       let->deliveredIP);
    else
	fprintf(f, "Received: from %s\n", let->deliveredIP);
    if ( !nullfrom )
	fprintf(f, "          (MAIL FROM:<%s>)\n", let->from->full);
    fprintf(f, "          by %s (TFMTKAYTFO)\n"
	       "          for %s (qid %s); %s\n",
		let->env->localhost,
		to->user ? to->user : to->fullname,
		let->qid, date);
}


void
copybody(FILE *f, struct letter *let)
{
    char *ptr;

    if (!let->has_headers)
	fputc('\n', f);

    fwrite(let->bodytext, let->bodysize, 1, f);
    fflush(f);
}


void
addheaders(FILE *f, struct letter *let)
{
    char msgtime[20];
    char date[80];

    strftime(date, 80, "%a, %d %b %Y %H:%M:%S %Z", localtime(&let->posted));
    strftime(msgtime, 20, "%d.%m.%Y.%H.%M.%S", localtime(&let->posted) );

    if (let->env->forged) {
	struct passwd *pw = getpwuid(let->env->sender);
	fprintf(f, "X-Authentication-Warning: <%s@%s> set sender to <%s>\n",
		    pw ? pw->pw_name : "postmaster",
		    let->deliveredto,
		    let->from->full);
    }
    if (!let->messageid)
	fprintf(f, "Message-ID: <%s.%s@%s>\n",
		    msgtime, let->qid, let->deliveredto);
    if (!let->mesgfrom)
	fprintf(f, "From: <%s>\n", let->from->full);
    if (!let->date)
	fprintf(f, "Date: %s\n", date);
#if 0
    fprintf(f, "X-Debug-Me: has_headers=%d,\n"
	       "            date=%d,\n"
	       "            mboxfrom=%d,\n"
	       "            messageid=%d,\n"
	       "            mesgfrom=%d\n",
		let->has_headers,
		let->date,
		let->mboxfrom,
		let->messageid,
		let->mesgfrom);
#endif
}


static int
domaincmp(struct recipient *a, struct recipient *b)
{
    return strcmp(a->host, b->host);
}

static char*
restofline(char *p, char *q)
{
    char *ret;
    int size = q-p;

    if (size <= 0) {
	syslog(LOG_ERR, "restofline alloc %d bytes", size);
	abort();
    }

    if ( ret = malloc(size+1) ) {
	memcpy(ret, p, size);
	ret[size] = 0;
	return ret;
    }
    syslog(LOG_ERR,"restofline alloc %d byte%s: %m",size,(size==1)?"s":"");
    abort();

} /* restofline */


int
readcontrolfile(struct letter *let, char *qid)
{
    int   fd;
    char  ctrlfile[sizeof(CTRLPFX)+6+1];
    char *ctrl = 0;
    long  size;
    char *sep;
    char *p, *q, *end;
    struct address to, *tmp;

    sprintf(ctrlfile, CTRLPFX "%.6s", qid);

    if ( (fd = open(ctrlfile, O_RDONLY)) != -1) {
	ctrl = mapfd(fd, &size);
	close(fd);
    }

    if (ctrl == 0) return 0;

    reset(let);

    strncpy(let->qid, qid, sizeof let->qid);

    p = ctrl;
    end = p + size;

    for (p = ctrl ; (p < end) && (q = memchr(p, '\n', end-p)); p = q+1) {
	switch (*p) {
	case C_FROM:		/* From: address */
		if (let->from)
		    freeaddress(let->from);
		if ( (let->from = calloc(1, sizeof let->from[0])) == 0 ) {
		    syslog(LOG_ERR, "out of memory");
		    abort();
		}
		if ( (let->from->full = restofline(1+p, q)) == 0) {
		    syslog(LOG_ERR, "out of memory");
		    abort();
		}
		let->from->domain = strdup(let->env->localhost);
		break;

	case C_TO:		/* To: address */
		memset(&to, 0, sizeof to);
		if ( (to.full = restofline(1+p, q)) == 0) {
		    syslog(LOG_ERR, "out of memory");
		    abort();
		}
		if ( ((sep = strchr(to.full, '|')) == 0) || (sep == to.full) ) {
		    syslog(LOG_ERR, "Qid %s: corrupted to address <%s>",
				    let->qid, to.full);
		    abort();
		}
		*sep++ = 0;
		to.domain = sep;

		if ( *to.domain == 0 ) {
		    syslog(LOG_ERR, "Qid %s: corrupted to address <%s>",
				    let->qid, to.full);
		    abort();
		}
		else if (newrecipient(&let->remote, &to, emUSER, -1, -1) == -1)
		    abort();
		free(to.full);
		break;

	case C_FLAGS:		/* extra flags */
		switch (p[1]) {
		case 'H':   let->has_headers = 1;
			    break;
		case 'F':   let->mesgfrom = 1;
			    break;
		}
		break;

	case C_HEADER:		/* real headers live past here */
		if (1+q < end) {
		    let->headtext = restofline(1+q, end);
		    let->headsize = end - (1+q);
		}
		else {
		    let->headtext = malloc(1);
		    let->headsize = 0;

		}
		munmap(ctrl,size);
		return 1;
	}
    }
    munmap(ctrl, size);
    return 0;
}


int
writecontrolfile(struct letter *let)
{
    FILE *f;
    char ctrlfile[sizeof(DATAPFX)+6+1];
    int count;

    /* after writing the data, write the control file
     */
    sprintf(ctrlfile, CTRLPFX "%s", let->qid);

    if ( (f=fopen(ctrlfile, "w")) != 0) {
	/* queue comments always come first.
	 */
	if (let->qcomment && let->qcomment[0])
	    fprintf(f, "%c%s\n", C_STATUS, let->qcomment);
	if (let->from->full && strlen(let->from->full) > 0)
	    if (let->from->domain && strlen(let->from->domain) > 0)
		fprintf(f, "%c%s\n", C_FROM, let->from->full);
	    else
		fprintf(f, "%c%s@%s\n",C_FROM,let->from->user,
				    let->env->localhost);

	for (count=let->remote.count; count-- > 0; )
	    if (let->remote.to[count].status == PENDING) {
		fprintf(f, "%c%s|%s\n", C_TO, let->remote.to[count].fullname,
					      let->remote.to[count].host);
	    }

	if (let->has_headers)
	    fprintf(f, "%cH ;has headers\n", C_FLAGS);
	if (let->mesgfrom)
	    fprintf(f, "%cF ;has from:\n", C_FLAGS);

	/* additional headers ALWAYS come at the end of the
	 * control message so we can cheat and simply spool them
	 * off the disk.
	 */
	fprintf(f, "%c%c ;additional headers\n", C_HEADER, C_HEADER);
	addheaders(f, let);

	if ( ferror(f) == 0 && fclose(f) == 0)
	    return 1;
	syslog(LOG_ERR, "can't write to controlfile: %m");
	fclose(f);
    }
    syslog(LOG_ERR, "can't save to controlfile: %m");
    return 0;
}


int
svspool(struct letter *let)
{
    int retry = 10;
    char spoolfile[sizeof(DATAPFX)+6+1];
    FILE *f;
    int count;

    /* No need to spool the file if it's only going to
     * local recipients
     */
    if (let->remote.count == 0) {
	unlink(let->tempfile);
	let->tempfile = 0;
	return 1;
    }

    /* after finishing the file, create the actual spoolfile
     * and rename the tempfile over to it.   Go around 10 times
     * if there's a race.
     */
    do {
	strcpy(spoolfile, DATAPFX "XXXXXX");

	if (mktemp(spoolfile) && (link(let->tempfile, spoolfile) == 0) )
	    break;
	if ( errno != EEXIST || retry <= 0) {
	    syslog(LOG_ERR, "can't save to spoolfile <%s -> %s>: %m",
			let->tempfile, spoolfile);
	    reset(let);
	    return 0;
	}
	sleep(1);
    } while (retry-- > 0);
    unlink(let->tempfile);
    let->tempfile = 0;

    strncpy(let->qid, spoolfile+strlen(DATAPFX), sizeof let->qid);

    if (writecontrolfile(let) == 0) {
	unlink(spoolfile);
	return 0;
    }
    return 1;
}
