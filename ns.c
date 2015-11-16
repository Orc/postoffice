#include "config.h"

#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include <stdio.h>
#include <string.h>

#if HAVE_MALLOC_H
#   include <malloc.h>
#endif

#include "mx.h"
/*
 * how the dns records look (roughly)
 *
 * each record has a HEADER (arpa/nameser.h), followed by 0+ QUERY
 * records and then 0+ ANSWER, NS, and AUTHORITY RECORDS.
 *
 * A QUERY record is a NAME, then 2 bytes query type and 2 bytes class
 * the other records are a NAME, then two bytes type, two bytes class,
 * 4 bytes ttl, 2 bytes size, then (size) bytes of returned value.
 *
 * A NAME is a chain of pascal strings for each segment in a domain
 * name.  PELL.PORTLAND.OR.US would be <4>PELL<8>PORTLAND<2>OR<2>US<0>
 *                                      |    | |        | |  | |  |
 *                                      +-one+ +---two--+ +-3+ +-4+
 * There is one optimization.  If the upper two bits (0xc0) of the
 * length are set, the rest of the name is pointed to by that byte
 * and the next one.   If the PELL.PORTLAND.OR.US above was located
 * at position 55 in the dns record, a second reference to it could
 * be done as <192><55> and a reference to ORC.PELL.PORTLAND.OR.US
 * would be <3>ORC<192><55>.   Note that the first NAME in a QUERY
 * record will always be a pointer, thus preserving the offsets
 * of the query type, class, ttl, and size.
 *
 */


void
say(char *what, short records)
{
    records = ntohs(records);

    printf("%d %s record%s\n", records, what, (records!=1)?"s":"");
}


char *
name(unsigned char *base, unsigned char *p)
{
    unsigned short size;
    unsigned short z;

    while ( (size = *p++) ) {
	if ( (size & 192) == 192) {
	    z  = (size & ~192) << 8;
	    z |= *p++;
	    putchar('{');
	    name (base, base + z);
	    putchar('}');
	    return (char*)p;
	}
	else {
	    for ( ; size-- > 0; ++p)
		putchar(*p);
	    putchar('.');
	}
    }
    return (char*)p;
}

char *
string(unsigned char *base, unsigned char *p)
{
    unsigned short size = *p++;

    printf("%.*s", size, p);

    return (char*)(p + size);
}


unsigned char *
word(unsigned char *q)
{
    unsigned short val;

    val  = (*q++) << 8;
    val |= (*q++);

    printf("%u", val);
    return q;
}


unsigned char *
dword(unsigned char *q)
{
    unsigned long val;
    int i;

    for (val=0, i=0; i < 4; i++) {
	val <<= 8;
	val |= *q++;
    }
    printf("%lu", val);
    return q;
}


unsigned char *
data(unsigned char *base, unsigned char *p)
{
    unsigned short dtype;
    unsigned short dclass;
    unsigned long  dttl;
    unsigned short count;
    unsigned short val;
    unsigned char *q;

    dtype = (*p++) << 8; dtype |= *p++;
    dclass= (*p++) << 8; dclass|= *p++;
    for (dttl=count=0; count < 4; count++)
	dttl = (dttl<<8) | (*p++);

    count  = (*p++) << 8; count |= (*p++);

    switch (dtype) {
    case 1:	/* A (IPV4) */
	fputs("[A]", stdout);
	fputs((char*)inet_ntoa(*(struct in_addr*)p), stdout);
	break;
    case 2:	/* NS */
	fputs("[NS]",stdout);
	name(base, p);
	break;
    case 5:	/* CNAME */
	fputs("[CNAME]",stdout);
	name(base, p);
	break;
    case 12:	/* PTR */
	fputs("[PTR]",stdout);
	name(base, p);
	break;
    case 13:	/* HINFO */
	fputs("[HINFO]",stdout);
	q = (unsigned char*)string(base, p);
	putchar(',');
	q = (unsigned char*)string(base, q);
	break;
    case 16:	/* TXT */
	fputs("[TXT]",stdout);
	q = (unsigned char*)string(base, p);
	break;
    case 6:	/* SOA */
	fputs("[SOA]",stdout);
	q = (unsigned char*)name(base, p);
	putchar(',');
	q = (unsigned char*)name(base, q);
	putchar(',');
	q = dword(q);
	putchar(',');
	q = dword(q);
	putchar(',');
	q = dword(q);
	putchar(',');
	q = dword(q);
	putchar(',');
	q = dword(q);
	break;

    case 15:	/* MX */
	fputs("[MX]",stdout);
	q = word(p);
	putchar(' ');
	return (unsigned char*)name(base, q);

    case 28:	/* AAAA */
	fputs("[AAAA]",stdout);
	for (val=0 ; count-- > 0; p++, val++)
	    printf("%s%d", val ? "." : "", (unsigned)*p);
	return p;

    default:
	printf("answer is (%d,%d) %d byte%s:", dtype, dclass, count, (count!=1)?"s":"");
	for ( ; count-- > 0 ; p++) {
	    if (isalnum(*p))
		putchar(*p);
	    else
		printf("<%02x>", *p);
	}
	return p;
    }
    return p+count;
}

#define Q(x)	{ x, #x }
struct query {
    short qtype;
    char *qname;
} query[] = {
    Q(T_A),     Q(T_NS),   Q(T_MD),   Q(T_MF),  Q(T_CNAME), Q(T_SOA),
    Q(T_MB),    Q(T_MR),   Q(T_NULL), Q(T_WKS), Q(T_PTR),   Q(T_HINFO),
    Q(T_MINFO), Q(T_MX),   Q(T_TXT),  Q(T_RP),  Q(T_AFSDB), Q(T_X25),
    Q(T_ISDN),  Q(T_RT),   Q(T_NSAP), Q(T_SIG), Q(T_KEY),   Q(T_PX),
    Q(T_GPOS),  Q(T_AAAA), Q(T_LOC),
};
#define NRQ	(sizeof query/sizeof query[0])


main(int argc, char **argv)
{
    char bfr[1024];
    int count;
    int ret;
    HEADER *hdr;
    unsigned size;
    unsigned char *p;
    unsigned char *q;
    char *host;
    unsigned short qtype = T_A;

    if (argc > 1 && argv[1][0] == ':') {
	for (count=0; count<NRQ; count++) {
	    if (strcasecmp(argv[1]+1, query[count].qname+2) == 0) {
		qtype = query[count].qtype;
		break;
	    }
	}
	++argv;
	--argc;
    }

    host = (argc>1)?argv[1]:"localhost";

    res_init();


    if (host[strlen(host)] == '.')
	ret = res_query(host, C_IN, qtype, (unsigned char*)bfr, sizeof bfr);
    else
	ret = res_search(host, C_IN, qtype, (unsigned char*)bfr, sizeof bfr);

    if (ret < 0) {
	herror(host);
	exit(1);
    }

    hdr = (HEADER*)&bfr;

    if (hdr->tc)
	printf("truncated.  Bother!\n");

    say("question", hdr->qdcount);
    say("answer",   hdr->ancount);
    say("authority",hdr->nscount);
    say("resource", hdr->arcount);

    p = (unsigned char*)(&hdr[1]);

    for (count=ntohs(hdr->qdcount); count>0; --count) {

	printf("query:");
	p = (unsigned char*)name ((unsigned char*)hdr, p);
	putchar('\n');

	/* skip type(x2)/class(x2) */
	p += 4;
    }

    for (count=ntohs(hdr->ancount); count>0; --count) {

	printf("answer:");
	p = (unsigned char*)name((unsigned char*)hdr, p);
	putchar(':');
	p = (unsigned char*)data((unsigned char*)hdr, p);
	putchar('\n');
    }

    for (count=ntohs(hdr->nscount); count>0; --count) {

	printf("authority:");
	p = (unsigned char*)name((unsigned char*)hdr, p);
	putchar(':');
	p = (unsigned char*)data((unsigned char*)hdr, p);
	putchar('\n');
    }

    for (count=ntohs(hdr->arcount); count>0; --count) {

	printf("resource:");
	p = (unsigned char*)name((unsigned char*)hdr, p);
	putchar(':');
	p = (unsigned char*)data((unsigned char*)hdr, p);
	putchar('\n');
    }
}
