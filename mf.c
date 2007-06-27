/*
 * sendmail "milter" interface
 */
#include "config.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#ifdef OS_FREEBSD
#include <malloc.h>
#else
#include <stdlib.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/un.h>

#ifdef DEBUG
#include <signal.h>
#endif

#define WITH_MILTER
#include "mf.h"


extern void message(FILE *f, int code, char *fmt, ...);

struct milter {
    char *socket;
    int   fd;
    int   flags;
#define SOFT	0x01
#define FAILED	0x02
#define DEAD	0x04
};

static struct milter *filters = 0;
static int nrfilters = 0;


int
mfregister(char *filter, char **opts)
{
    filters = filters ? realloc(filters, (1+nrfilters)*sizeof filters[0])
		      : malloc(sizeof filters[0]);
    
    if (filters == 0)
	nrfilters = 0;
    else {
	filters[nrfilters].socket = strdup(filter);
	filters[nrfilters].fd = -1;
	filters[nrfilters].flags = SOFT;
	++nrfilters;
    }
    return nrfilters;
}


static int
xread(int fd, void *ptr, int size)
{
    int ret, left=size;

    do {
	if ( (ret = read(fd, ptr, left)) <= 0 )
	    return ret ? -1 : left;
	ptr += ret;
	left -= ret;
    } while (left > 0);

    return size;
}


static int maxsize = 0;
static struct mfdata *lastpkt = 0;


char *
mfresult()
{
    return ( lastpkt && (lastpkt->data[0] == 'y') ) ? 1 + lastpkt->data : 0;
}


int
mfcode()
{
    if (lastpkt == 0)
	return 554;
    if (lastpkt->data[0] == 'y') {
	char *p = 1 + lastpkt->data;
	if (isdigit(*p))
	    return atoi(p);
    }
    else if (lastpkt->data[0] == 't')
	return 454;
    return 554;
}


void
mfcomplain(struct letter *let, char *generic)
{
    char *q = mfresult();
    int code = mfcode();

    if (q) {
	while (isdigit(*q) || isspace(*q) || *q == '.') ++q;

	message(let->out, code, q);
    }
    else
	message(let->out, code, "%s", generic);
}


static struct mfdata *
mread(int f)
{
	DWORD nwsize;
	DWORD size;

	if (xread(f, &nwsize, 4) != 4)
		return 0;
	
	size = ntohl(nwsize);


	if (size > maxsize) {
	    lastpkt = lastpkt ? realloc(lastpkt, sizeof(lastpkt->size) + size)
			      : malloc(sizeof(lastpkt->size) + size);
	    maxsize = size;
	}
	if (lastpkt == 0)
		return 0;
	
	lastpkt->size = size;
	if (xread(f, lastpkt->data, size) != size)
		return 0;

	return lastpkt;
}

static int
mdscanf(struct mfdata *f, char *fmt, ...)
{
    va_list ptr;
    char *p;
    DWORD l;
    WORD s;
    int leftover;
    char *restofbuf;
    int results = 0;

    int i;
    char *q;

    if (f == 0)
	return EOF;

    leftover = f->size - 1;
    restofbuf= f->data + 1;
    
    va_start(ptr,fmt);
    for (p = fmt; *p; ++p) {
	if ( (*p == '%') && p[1]) {
	    switch (*++p) {
	    case 'l':
		if (leftover < 4)
		    break;
		memcpy(&l, restofbuf, 4);
		restofbuf += 4;
		leftover -= 4;
		*va_arg(ptr,DWORD*) = ntohl(l);
		results++;
		break;
	    case 'd':
		if (leftover < 2)
		    break;
		memcpy(&s, restofbuf, 2);
		restofbuf += 2;
		leftover -= 2;
		*va_arg(ptr, WORD*) = ntohs(s);
		results++;
		break;
	    case 'c':
		if (leftover < 1)
		    break;
		*va_arg(ptr,char*) = *restofbuf++;
		leftover--;
		results++;
		break;

	    case 's':
		for (i=leftover, q=restofbuf; i>=0; --i, ++q)
		    if (*q == 0)
			break;
		if (i < 0)
		    break;
		
		*va_arg(ptr,char**) = strdup(restofbuf);
		leftover -= 1+strlen(restofbuf);
		restofbuf+= 1+strlen(restofbuf);
		results++;
		break;
	    }
	}
    }
    va_end(ptr);

    return results;
}


static int
mfprintf(int f, char cmd, char *fmt, ...)
{
    va_list ptr;
    int size = 1;
    char   *p, *q;
    DWORD  nw32;
    WORD   nw16;
    char   c[1];
    int    rc, len;

    va_start(ptr,fmt);

    for (p = fmt; *p; ++p) {
	if ( (*p == '%') && p[1]) {
	    switch (*++p) {
	    case 'l':   size += 4;
			va_arg(ptr,DWORD);
			break;
	    case 'd':   size += 2;
			va_arg(ptr,int);
			break;
	    case 'c':   size++;
			va_arg(ptr,int);
			break;
	    case '*':	size += va_arg(ptr,int);
			break;
	    case 's':   q = va_arg(ptr,char*);
			size += strlen(q) + 1;
			break;
	    }
	}
    }

    va_end(ptr);

    nw32 = htonl(size);

    c[0] = cmd;
    if (write(f, &nw32, 4) != 4 || write(f, c, 1) != 1)
	return 0;

    va_start(ptr, fmt);
    for (p = fmt; *p; ++p) {
	rc = 1;
	if ( (*p == '%') && p[1]) {
	    switch (*++p) {
	    case 'l':   nw32 = htonl(va_arg(ptr,DWORD));
			rc = write(f, &nw32, 4) == 4;
			break;
	    case 'd':   nw16 = htons(va_arg(ptr,int));
			rc = write(f, &nw16, 2) == 2;
			break;
	    case 'c':   c[0] = va_arg(ptr, int);
			rc = write(f, c, 1) == 1;
			break;
	    case '*':	len = va_arg(ptr, int);
			rc = write(f, va_arg(ptr,char*), len) == len;
			break;
	    case 's':   q = va_arg(ptr, char*);
			rc = write(f, q, strlen(q)+1) == strlen(q)+1;
			break;
	    }
	}
	if (!rc) break;
    }
    va_end(ptr);
    return rc;
}


static int
mreply(int f)
{
    struct mfdata *ret;

    while ( (ret = mread(f)) && (ret->size > 0) ) {
	switch (ret->data[0]) {
	case 'p':   break;	/* no-op */
	case 'r':
	case 'd':   return MF_REJ;
	case 'y':   return MF_REJ_CODE;
	case 'b':   return MF_REJ; /* wanting to replace the message == error */
	case 't':   return MF_TEMP;
	default:    return MF_OK;
	}
    }
    return MF_EOF;
}


static int
handshake(struct letter *let, char *channel)
{
    int f;
    int rc;
    struct mfdata *ret;
    struct sockaddr_un urk;
    int len;
    DWORD rflags, rhandshake, rversion;

    if (channel[0] == '/') {
	/* connect to named socket
	 */
	if (strlen(channel) > sizeof urk.sun_path) {
	    fprintf(stderr, "%s: too long for socket\n", channel);
	    return -1;
	}

	if ( (f = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
	    perror("socket");
	    return -1;
	}

	urk.sun_family = AF_UNIX;
	strncpy(urk.sun_path, channel, sizeof urk.sun_path);
	len = strlen(urk.sun_path) + sizeof(urk.sun_family);

	if ( connect(f, (struct sockaddr*)&urk, len) != 0 ) {
	    perror(channel);
	    close(f);
	    return -1;
	}
    }
    else {
	/* connect to tcp/ip socket.. copy this code from the smtp client
	 * code. */
	return -1;
    }


    mfprintf(f, 'O', "%l%l%l", 2, 0xff, 0);
    if ( (ret = mread(f)) && (ret->data[0] == 'O') 
			  && (mdscanf(ret, "%l%l%l", &rversion, &rflags,
						     &rhandshake) == 3) ) {

	mfprintf(f, 'C', "%s%c%d%s", let->deliveredby, '4', 25,
				     let->deliveredIP);
	if (mreply(f) == MF_OK)
	    return f;
    }
    close(f);
    return -1;
}


int
mfconnect(struct letter *let)
{
    int i;

    for (i=0; i < nrfilters; i++) {
	if ( (filters[i].fd = handshake(let, filters[i].socket)) == -1) {
	    filters[i].flags |= FAILED;
	    if ( (filters[i].flags & SOFT) == 0 )
		return MF_REJ;
	}
    }
    return MF_OK;
}


#define FORALL(args)	\
    int i, status; \
    for (i=0; i < nrfilters; i++) \
	if ( (filters[i].fd != -1) && (filters[i].flags & FAILED) == 0 ) { \
	    mfprintf args; \
	    if ( (status = mreply(filters[i].fd)) != MF_OK ) { \
		filters[i].flags |= FAILED; \
		if ( (filters[i].flags & SOFT) == 0 ) \
		    return status; \
	    } \
	} \
    return MF_OK


int
mfheader(struct letter *let,  char *start, char *sep, char *end)
{
    char *header = alloca(1 + (sep-start));
    char *content= alloca(1 + (end-sep));

    memcpy(header, start, sep-start);
    header[sep-start] = 0;
    memcpy(content,sep+1, (end-sep)-1);
    content[end-sep-1] = 0;


    {
	FORALL( (filters[i].fd, 'L', "%s%s", header, content) );
    }
}

static int
mfeoh()
{
    FORALL( (filters[i].fd, 'N', "") );
}

static int
mfchunk(char *p, int size)
{
    FORALL( (filters[i].fd, 'B', "%*", size, p) );
}

int
mfhelo(struct letter *let, char *hellostring)
{
    FORALL( (filters[i].fd, 'H', "%s", hellostring) );
}


int
mffrom(struct letter *let, char *from)
{
    FORALL( (filters[i].fd, 'M', "%s", from) );
}

int
mfto(struct letter *let, char *to)
{
    FORALL( (filters[i].fd, 'R', "%s", to) );
}


int
mfreset(struct letter *let)
{
    int i;

    for (i=0; i < nrfilters; i++)
	if (filters[i].fd != -1) {
	    mfprintf(filters[i].fd, 'A', "");
	    filters[i].flags &= ~FAILED;
	}
    return MF_OK;
}

int
mfquit(struct letter *let)
{
    int i;

    for (i=0; i < nrfilters; i++)
	if (filters[i].fd != -1) {
	    mfprintf(filters[i].fd, 'Q', "");
	    close(filters[i].fd);
	    filters[i].fd = -1;
	}
    return MF_OK;
}


int
mfeom()
{
    int i;
    int status;

    for (i=0; i < nrfilters; i++)
	if ( (filters[i].flags & FAILED) == 0 ) {
	    mfprintf(filters[i].fd, 'E', "");
	    do {
		if ( (status=mreply(filters[i].fd)) == MF_EOF ) {
		    filters[i].flags |= FAILED;
		    return MF_REJ;
		}
	    } while ( strchr("acdrty", lastpkt->data[0]) == 0 );
	    if (status != MF_OK)
		return status;
	}
    return MF_OK;
}


int
mfdata(struct letter *let)
{
    char *p, *q, *c;
    int size = let->bodysize;
    char *map = let->bodytext,
         *end = let->bodytext + size;
    int status;
#define MCHUNKSIZE	65535

    for (p = map; p < end; p = 1+q) {
	int checked = 0;

	/* find a newline */
	if ( (q = memchr(p, '\n', size - (p - map))) == 0)
		break;
	/* find a : on this line or fail */
	if ( (c = memchr(p, ':', q-p)) == 0)
	    break;

	/* valid header line.  grab continuation lines */
	while ( (q+1 < p+size) && (q[1] == '\t' || q[1] == 'n') ) {
	    char *q2;

	    if ( (q2 = memchr(q+1, '\n', size - (q - map) - 1)) != 0 )
		q = q2;
	    else
		q = p+size;
	}
	/* [p .. q-1] is a valid header, perhaps.  Send it */
	if ( (status = mfheader(let,p,c,q)) != MF_OK )
	    return status;
    }
    /* end of file or blank/malformed line == no more headers */

    if ( (status = mfeoh()) != MF_OK )
	return status;

    while ( p < end ) {
	int chunk;

	chunk = (p+MCHUNKSIZE < map+size) ? MCHUNKSIZE : (map+size) - p;

	if ( (status = mfchunk(p, chunk)) != MF_OK )
	    return status;
	p += chunk;
    }
    status = mfeom();
    return status;
}


#if DEBUG

void message(FILE* q,int r,char* s, ...)
{
}

double
main(int argc, char **argv)
{
    int i;
    register c;
    FILE *message;
    int input;
    struct letter let;
    struct stat st;
    char *code;

    signal(SIGPIPE, SIG_IGN);

    if ( (argc < 2) ) {
	fprintf(stderr, "usage: mf <socket> ... < mailmsg\n");
	exit(1);
    }

    bzero(&let, sizeof let);
    let.deliveredby = "localhost";
    let.deliveredIP = "127.0.0.1";


    if (isatty(0)) {
	if ( (message = tmpfile())  == 0) {
	    perror("can't copy input file");
	    exit(1);
	}

	while ((c = getchar()) != EOF)
	    fputc(c, message);
	fflush(message);
	input = fileno(message);
    }
    else
	input = 0;

    if (fstat(input, &st) != 0) {
	perror("fstat(input)");
	exit(1);
    }

    let.bodysize = st.st_size;
    let.bodytext = mmap(0, let.bodysize, PROT_READ, MAP_SHARED, input, 0);

    if ( let.bodytext == (void*)-1 ) {
	perror("mmap(input)");
	exit(1);
    }

    for (i=1; i < argc; i++)
	mfregister(argv[i], 0);


    printf("connect: %s\n", mfconnect(&let) ? "failed" : "ok");
    printf("helo   : %s\n", mfhelo(&let, "world") ? "failed" : "ok");
    printf("from   : %s\n", mffrom(&let, "<orc>") ? "failed" : "ok");
    printf("to     : %s\n", mfto(&let, "<orc>") ? "failed" : "ok");
    printf("data   : %s\n", mfdata(&let) ? "failed" : "ok");
    if ( code = mfresult() ) {
	int status = mfcode();
	while (isdigit(*code) || isspace(*code) || *code == '.') ++code;
	printf("%03d %s\n", status, code);
    }
    printf("reset  : %s\n", mfreset(&let) ? "failed" : "ok");
    printf("quit   : %s\n", mfquit(&let) ? "failed" : "ok");
    exit(0);
}
#endif