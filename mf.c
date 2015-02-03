/*
 * sendmail "milter" interface
 */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#ifdef HAVE_MALLOC_H
#   include <malloc.h>
#endif
#if HAVE_ALLOCA_H
#   include <alloca.h>
#endif
#include <ctype.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/un.h>

#ifdef DEBUG
#include <signal.h>
#define PERROR(x)	perror(x)
#ifndef WITH_MILTER
#define WITH_MILTER 1
#endif
#else
#define	PERROR(x)	
#endif

#include "mf.h"
#include "mx.h"
#include "socklib.h"
#include "cstring.h"


extern void message(FILE *f, int code, char *fmt, ...);

struct milter {
    char *socket;
    int   fd;
    int   flags;
#define HARD	0x01
#define FAILED	0x02
#define DEAD	0x04
    DWORD rflags;
#define ADD_HDRS	0x01	/* milter wants to add headers */
#define EDIT_DATA	0x02	/* milter wants to edit the message */
#define ADD_TO		0x04	/* milter wants to add recipients */
#define DEL_TO		0x08	/* milter wants to delete recipients */
#define EDIT_HDRS	0x10	/* milter wants to edit headers */
#define ISOLATE		0x20	/* milter wants to quarantine the message */
    DWORD pflags;
#define SKIP_CONN	0x01	/* don't do connect message */
#define SKIP_HELO	0x02	/* don't do helo message */
#define SKIP_FROM	0x04	/* or MAIL FROM: */
#define SKIP_TO		0x08	/* or RCPT TO: */
#define SKIP_DATA	0x10	/* or send the data */
#define SKIP_HDRS	0x20	/* ... or headers */
#define SKIP_EOH	0x40
};

static struct milter *filters = 0;
static int nrfilters = 0;


int
mfregister(char *filter, char **opts)
{
#if WITH_MILTER
    filters = filters ? realloc(filters, (1+nrfilters)*sizeof filters[0])
		      : malloc(sizeof filters[0]);
    
    if (filters == 0)
	nrfilters = 0;
    else {
	memset(&filters[nrfilters], 0, sizeof filters[nrfilters]);
	filters[nrfilters].socket = strdup(filter);
	filters[nrfilters].fd = -1;
	++nrfilters;
    }
#endif
    return nrfilters;
}


void
mflist(FILE *out, int rc)
{
#if WITH_MILTER
    int i;
    char flags[80];
    int flag;

    for (i=0; i < nrfilters; i++) {
	flags[0] = 0;
	flag = filters[i].flags;

	if (flag & HARD)
	    strcat(flags, "hard");
	if (flag & ~HARD) {
	    if (flag & FAILED) strcat(flags, " failed");
	    if (flag & DEAD) strcat(flags, " dead");
	    if (flag & ~(HARD|FAILED|DEAD))
		sprintf(flags+strlen(flags), " %02xh",
						flag & ~(HARD|FAILED|DEAD));
	}
	else strcat(flags, " ok");

	message(out, rc, "filter:[<%s>]%s", filters[i].socket, flags);
    }
#endif
}


#if WITH_MILTER
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
#endif


#if WITH_MILTER
static void
allfail()
{
    int i;
    for ( i=0; i < nrfilters; i++)
	filters[i].flags |= FAILED;
}
#endif


static int maxsize = 0;
static struct mfdata *lastpkt = 0;


char *
mfresult()
{
#if WITH_MILTER
    return ( lastpkt && (lastpkt->data[0] == 'y') ) ? 1 + lastpkt->data : 0;
#else
    return 0;
#endif
}


int
mfcode()
{
#if WITH_MILTER
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
#else
    return 0;
#endif
}


void
mfcomplain(struct letter *let, char *generic)
{
#if WITH_MILTER
    char *q = mfresult();
    int code = mfcode();

    if (q) {
	while (isdigit(*q) || isspace(*q) || *q == '.') ++q;

	message(let->out, code, q);
    }
    else
	message(let->out, code, "%s", generic);
#endif
}


#if WITH_MILTER
static struct mfdata *
mread(struct milter *f)
{
    DWORD nwsize;
    DWORD size;

    if (xread(f->fd, &nwsize, 4) != 4)
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
    if (xread(f->fd, lastpkt->data, size) != size)
	    return 0;

    return lastpkt;
}
#endif

#if WITH_MILTER
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
#endif


#if WITH_MILTER
static int
vmfprintf(struct milter *f, char cmd, char *fmt, va_list ptr)
{
    char   *p, *q;
    DWORD  nw32;
    WORD   nw16;
    int    len;

    static Cstring printbuf = { 0 };

    if ( ALLOCATED(printbuf) == 0 )
	RESERVE(printbuf,512);

    S(printbuf) = 5; /* 4 bytes length, 1 byte command */
    T(printbuf)[4] = cmd;

    for (p = fmt; *p; ++p) {
	if ( (*p == '%') && p[1]) {
	    switch (*++p) {
	    case 'l':   nw32 = htonl(va_arg(ptr,DWORD));
			SUFFIX(printbuf, &nw32, 4);
			break;
	    case 'd':   nw16 = htons(va_arg(ptr,int));
			SUFFIX(printbuf, &nw16, 2);
			break;
	    case 'c':   EXPAND(printbuf) = (char)va_arg(ptr, int);
			break;
	    case '*':	len = va_arg(ptr, int);
			SUFFIX(printbuf, va_arg(ptr,char*), len);
			break;
	    case '0':   EXPAND(printbuf) = 0;
			break;
	    case 's':   q = va_arg(ptr, char*);
			len = strlen(q) + 1;
			SUFFIX(printbuf, q, len);
			break;
	    }
	}
	else
	    EXPAND(printbuf) = *p;
    }
    nw32 = htonl(S(printbuf)-4);
    memcpy(T(printbuf), &nw32, 4);
#if 0
{   int i;
    fprintf(stderr, "Write %d bytes to %d: [", S(printbuf), f->fd);
    for (i=0; i < S(printbuf); i++)
	if ( isprint(T(printbuf)[i]) )
	    fprintf(stderr, " %c ", T(printbuf)[i]);
	else
	    fprintf(stderr, "$%02x", ((unsigned char*)T(printbuf))[i]);
    fprintf(stderr, "]\n");
}
#endif

    return write(f->fd, T(printbuf), S(printbuf));
}


static int
mfprintf(struct milter *f, char cmd, char *fmt, ...)
{
    va_list ptr;
    int rc;

    va_start(ptr, fmt);
    rc = vmfprintf(f,cmd,fmt,ptr);
    va_end(ptr);
    return rc;
}
#endif


#if WITH_MILTER
static int
mreply(struct milter *mf)
{
    struct mfdata *ret;

    while ( (ret = mread(mf)) && (ret->size > 0) ) {
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
#endif


#if WITH_MILTER
static int
handshake(struct letter *let, struct milter *mf)
{
    struct mfdata *ret;
    struct sockaddr_un urk;
    int len;
    DWORD rrflags, rpflags, rversion;

    if (mf->socket[0] == '/') {
	/* connect to named socket
	 */
	if (strlen(mf->socket) > sizeof urk.sun_path)
	    return -1;

	if ( (mf->fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
	    PERROR("socket");
	    return -1;
	}

	urk.sun_family = AF_UNIX;
	strncpy(urk.sun_path, mf->socket, sizeof urk.sun_path);
	len = strlen(urk.sun_path) + sizeof(urk.sun_family);

	if ( connect(mf->fd, (struct sockaddr*)&urk, len) != 0 ) {
	    PERROR(mf->socket);
	    close(mf->fd);
	    return -1;
	}
    }
    else {
	/* connect to IP port
	 */
	char *p;
	struct iplist list;
	int i, port;
	char *ipchan = alloca(strlen(mf->socket)+1);

	strcpy(ipchan, mf->socket);

	if ( (p = strchr(ipchan, ':')) == 0 )
	    return -1;	/* format is host:port */

	*p++ = 0;

	if ( (port = atoi(p)) <= 0)
	    return -1;	/* bogus port */

	if (getIPa(ipchan, IP_NEW, &list) <= 0)
	    return -1;

	for (mf->fd = -1, i=list.count; i > 0; --i)
	    if ( (mf->fd = attach_in(&(list.a[i-1].addr), port)) != -1 )
		break;

	freeiplist(&list);
	if (mf->fd == -1)
	    return -1;	/* could not connect to socket */
    }

    mfprintf(mf, 'O', "%l%l%l", 2, 0xff, 0xff);

    if ( (ret = mread(mf)) && (ret->data[0] == 'O') 
			   && (mdscanf(ret, "%l%l%l", &rversion, &rrflags,
						      &rpflags) == 3) ) {
	mf->rflags = rrflags;
	mf->pflags = rpflags;

	if ( mf->pflags & SKIP_CONN )
	    return 0;
	else {
	    mfprintf(mf, 'C', "%s%c%d%s", let->deliveredby, '4', 25,
					  let->deliveredIP);
	    if (mreply(mf) == MF_OK)
		return 0;
	}
    }
    close(mf->fd);
    return -1;
}
#endif


int
mfconnect(struct letter *let)
{
#if WITH_MILTER
    int i;

    for (i=0; i < nrfilters; i++) {
	if ( handshake(let, &filters[i]) == -1) {
	    filters[i].flags |= FAILED;
	    if ( filters[i].flags & HARD )
		return MF_REJ;
	}
    }
#endif
    return MF_OK;
}


static int
foreach(int unless, char cmd, char *fmt, ...)
{
#if WITH_MILTER
    int i, status;
    va_list ptr;

    for (i=0; i < nrfilters; i++)
	if ( filters[i].flags & FAILED )
	    continue;
	else if ( filters[i].pflags & unless )
	    continue;
	else {
	    va_start(ptr, fmt);
	    vmfprintf(&filters[i], cmd, fmt, ptr);
	    va_end(ptr);
	    if ( (status = mreply(&filters[i])) == MF_EOF) {
		filters[i].flags |= FAILED|DEAD; 
		if ( filters[i].flags & HARD ) {
		    allfail();
		    return MF_TEMP; 
		}
	    }
	    else if (status != MF_OK) {
		if ( status != MF_TEMP )
		    allfail();
		return status;
	    }
	}
#endif
    return MF_OK;
}

int
mfheader(struct letter *let,  char *start, char *sep, char *end)
{
#if WITH_MILTER
    char *header = alloca(1 + (sep-start));
    char *content= alloca(1 + (end-sep));

    memcpy(header, start, sep-start);
    header[sep-start] = 0;
    memcpy(content,sep+1, (end-sep)-1);
    content[end-sep-1] = 0;
#endif
    return foreach(SKIP_HDRS, 'L', "%s%s", header, content);
}

#if WITH_MILTER
static int
mfeoh()
{
    return foreach(SKIP_EOH, 'N', "" );
}
#endif

#if WITH_MILTER
static int
mfchunk(char *p, int size)
{
    return foreach(SKIP_DATA, 'B', "%*", size, p);
}
#endif

int
mfhelo(struct letter *let, char *hellostring)
{
    return foreach(SKIP_HELO, 'H', "%s", hellostring);
}


/* strip the \r\n off the end of a line
 */
static int
withoutnl(char *text)
{
    int total = strlen(text);

    if ( total > 0 && text[total-1] == '\n') --total;
    if ( total > 0 && text[total-1] == '\r') --total;

    return total;
}

int
mffrom(struct letter *let, char *from)
{
    return foreach(SKIP_FROM, 'M', "%*%0", withoutnl(from), from );
}

int
mfto(struct letter *let, char *to)
{
    return foreach(SKIP_TO, 'R', "%*%0", withoutnl(to), to );
}


int
mfreset(struct letter *let)
{
#if WITH_MILTER
    int i;

    for (i=0; i < nrfilters; i++)
	if (filters[i].fd != -1) {
	    mfprintf(&filters[i], 'A', "");
	    filters[i].flags &= ~FAILED;
	}
#endif
    return MF_OK;
}

int
mfquit(struct letter *let)
{
#if WITH_MILTER
    int i;

    for (i=0; i < nrfilters; i++)
	if (filters[i].fd != -1) {
	    mfprintf(&filters[i], 'Q', "");
	    close(filters[i].fd);
	    filters[i].fd = -1;
	}
#endif
    return MF_OK;
}


int
mfeom()
{
#if WITH_MILTER
    int i;
    int status;

    for (i=0; i < nrfilters; i++)
	if ( (filters[i].flags & FAILED) == 0 ) {
	    mfprintf(&filters[i], 'E', "");
	    do {
		if ( (status=mreply(&filters[i])) == MF_EOF ) {
		    filters[i].flags |= FAILED|DEAD;
		    if (filters[i].flags & HARD)
			return MF_REJ;
		    status = MF_OK;
		    break;
		}
	    } while ( strchr("acdrty", lastpkt->data[0]) == 0 );
	    if (status != MF_OK)
		return status;
	}
#endif
    return MF_OK;
}


int
mfdata(struct letter *let)
{
    int status;
#if WITH_MILTER
    char *p, *q, *c;
    int size = let->bodysize;
    char *map = let->bodytext,
         *end = let->bodytext + size;
#define MCHUNKSIZE	65535

    for (p = map; p < end; p = q) {
	/* find a newline */
	if ( (q = memchr(p, '\n', size - (p - map))) == 0)
		break;
	/* find a : on this line or fail */
	if ( (c = memchr(p, ':', q-p)) == 0)
	    break;

	/* valid header line.  grab continuation lines */
	for (++q; (q < map+size) && isspace(*q) && (*q != '\n'); ++q) {
	    if ( (q = memchr(q, '\n', size - (q - map))) == 0 )
		q = map+size;
	}
	/* [p .. q-1] is a valid header, perhaps.  Send it */
	if ( (status = mfheader(let,p,c,q-1)) != MF_OK )
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
#endif
    status = mfeom();
    return status;
}


#if DEBUG

void message(FILE* q,int r,char* s, ...)
{
}


void
mfwhy()
{
    char *code;

    if ( code = mfresult() ) {
	int status = mfcode();
	while (isdigit(*code) || isspace(*code) || *code == '.') ++code;
	printf("%03d %s\n", status, code);
    }
}

mfdo(struct letter *let, char *phase, int status)
{
    printf("%-7.7s: %s\n", phase, status ? "failed" : "ok");
    if ( status ) {
	mfwhy();
	if ( strcmp(phase, "quit") != 0 )
	    mfquit(let);
	exit(1);
    }
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
    let.deliveredIP = "127.0.0.2";


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


    mfdo(&let, "connect", mfconnect(&let));
    mfdo(&let, "helo",    mfhelo(&let, "world"));
    mfdo(&let, "from",    mffrom(&let, "<orc>"));
    mfdo(&let, "to",      mfto(&let, "<orc>"));
    mfdo(&let, "data",    mfdata(&let));
    mfdo(&let, "reset",   mfreset(&let));
    mfdo(&let, "quit",    mfquit(&let));
    exit(0);
}
#endif
