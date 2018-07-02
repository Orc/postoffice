#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <syslog.h>
#include <time.h>
#include <setjmp.h>
#include <stdarg.h>

#if HAVE_MALLOC_H
#   include <malloc.h>
#endif

#include "spool.h"

#include "letter.h"
#include "env.h"
#include "mx.h"


static int
hprintf(jmp_buf *fail, struct letter *let, char *fmt, ...)
{
    va_list ptr;
    int gap, written;
    char *eoh;

    if ( let->headtext == 0 ) {
	let->headalloc = 800;
	let->headsize = 0;
	let->headtext = calloc(let->headalloc, 1);
    }
    if ( let->headalloc < let->headsize ) 
	let->headalloc = let->headsize;

    while (1) {
	if ( let->headtext == 0 )
	    longjmp(*fail, 1);
	    
	gap = let->headalloc - let->headsize;
	eoh = let->headtext + let->headsize;

	va_start(ptr, fmt);
	written = vsnprintf(eoh, gap, fmt, ptr);
	va_end(ptr);
	if ( written > 0 && written < gap ) {
	    let->headsize += written;
	    return 0;
	}
	let->headalloc *= 2;
	let->headtext = realloc(let->headtext, let->headalloc);
    }
    /* notreached */
}


/*
 * add a new header to the letter
 */
int
anotherheader(struct letter *let, char *key, char *data)
{
    int needed, i;
    
    if (let == 0 || key == 0 || data == 0) return 0;

    needed = strlen(key) + 2 /* :0x20 */ + strlen(data) + 1 /* \n */;


    if ( let->headtext == 0 ) {
	let->headalloc = needed+1;
	let->headsize = 0;
	let->headtext = calloc(1, let->headalloc);
    }
    else if ( let->headsize + needed > let->headalloc ) {
	let->headalloc += (1+needed);
	let->headtext = realloc(let->headtext, let->headalloc);
    }
    
    if (let->headtext == 0)
	return 0;

    let->headsize += sprintf(let->headtext+let->headsize, "%s: ", key);
    /* sanitize the data so it doesn't include any newlines
     */
    for (i=0; data[i]; i++)
	let->headtext[let->headsize++] = (data[i] == '\r' || data[i] == '\n')
					    ? ' '
					    : data[i];
    let->headtext[let->headsize++] = '\n';
    let->headtext[let->headsize] = 0;	/* null terminate, just to be safe */
    return 1;
}


static void
receivedby(jmp_buf *fail, struct letter *let, struct recipient *to)
{
    char date[80];
    int nullfrom = notnull(let->from);

    if (let->deliveredIP == 0) return;

    strftime(date, 80, "%a, %d %b %Y %H:%M:%S %Z", localtime(&let->posted));
    if (strcmp(let->deliveredby, let->deliveredIP) != 0)
	hprintf(fail, let, "Received: from %s (%s)", let->deliveredby,
					     let->deliveredIP);
    else
	hprintf(fail, let, "Received: from %s", let->deliveredIP);
    if ( !nullfrom )
	hprintf(fail, let, "\n          (MAIL FROM:<%s>)", let->from->full);
    hprintf(fail, let, "\n          by %s (TFMTKAYTFO)", let->env->localhost);
    if (to && to->fullname)
	hprintf(fail, let,"\n          for %s", to->fullname);
    hprintf(fail, let, " (qid %s); %s\n", let->qid, date);
}


void
addheaders(FILE *f, struct letter *let)
{
#if 0
    fprintf(stderr, "X-Debug-Me: has_headers=%d,\n"
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
    if (let->headtext && (let->headsize > 1) ) {
	fwrite(let->headtext,let->headsize,1,f);
#if 0
	fwrite(let->headtext,let->headsize,1,stderr);
#endif
    }

}


static int
headervalidate(struct letter *let, char* text, size_t size)
{
#define ISHDR(p,f)	(strncasecmp(p,f,strlen(f)) == 0)
    char *p, *ep;
    int has_headers = 0;
    int contin = 0;
    
    for (p = text, ep = p+size ; p && (p < ep); ) {
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

	    has_headers = 1;
	    p = memchr(p, '\n', (ep-p));
	}
	else if (*p == '\n')
	    break;

	if (p) ++p;
    }
    return has_headers;
}





int
examine(struct letter *let)
{
    char msgtime[20];
    char date[80];
    struct passwd *pwd;
    jmp_buf fail;

    fflush(let->body);

    if ( (let->bodytext = mapfd(fileno(let->body), &let->bodysize)) == 0 ) {
	syslog(LOG_ERR, "cannot mmap() the email body: %m");
	return 0;
    }

    /* check the message for headers */
    let->has_headers = headervalidate(let, let->bodytext,let->bodysize);

    
    strftime(date, 80, "%a, %d %b %Y %H:%M:%S %Z", localtime(&let->posted));
    strftime(msgtime, 20, "%d.%m.%Y.%H.%M.%S", localtime(&let->posted) );

    if ( setjmp(fail) != 0 ) {
	/* let's fake a try block :-) */
	syslog(LOG_ERR, "out of memory allocating headers");
	return 0;
    }
	
    receivedby(&fail, let, let->local.count > 0 ? let->local.to : 0);
    
    if (let->env->forged) {
	struct passwd *pw = getpwuid(let->env->sender);
	hprintf(&fail, let, "X-Authentication-Warning: <%s@%s> set sender to <%s>\n",
		    pw ? pw->pw_name : "postmaster",
		    let->deliveredto,
		    let->from->full);
    }
    if (!let->messageid) {
	hprintf(&fail, let, "Message-ID: <%s.%s@%s>\n",
		    msgtime, let->qid, let->env->localhost);
    }
    if (!let->mesgfrom) {
	if (let->from->domain)
	    hprintf(&fail, let, "From: <%s>\n", let->from->full);
	else if ((pwd = getpwnam(let->from->full)) && pwd->pw_gecos[0] )
	    hprintf(&fail, let, "From: \"%s\" <%s@%s>\n",
				pwd->pw_gecos,
				let->from->full, let->env->localhost);
	else
	    hprintf(&fail, let, "From: <%s@%s>\n", let->from->full, let->env->localhost);
    }

    if (!let->date)
	hprintf(&fail, let, "Date: %s\n", date);

    
    return 1;
}
