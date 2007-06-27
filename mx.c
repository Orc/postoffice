/*
 * get back a list of MXes for a site
 */

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include <stdio.h>
#include <string.h>

#if OS_FREEBSD
#   include <stdlib.h>
#else
#   include <malloc.h>
#endif

#include "mx.h"


static struct in_addr* localhost = 0;




/*
 * revolve CNAMEs for the host,
 * then get a list of MXes.  If that
 * list is null, get a list of MXes for
 * *.host.
 *
 * if the list is NOT null, get the
 * ips for that list (doing cname resolution)
 * otherwise get the IPs for the 
 * host
 */

struct dns_rec {
    unsigned char *eod;
    int   alloc;
    HEADER h;
#define DDATASZ	8196-sizeof(HEADER)
    unsigned char data[DDATASZ];
};

typedef struct dns_rec DNS_REC;


struct mx {
    short priority;
    char *name;
};

struct mxlist {
    int size, count;
    struct mx *host;
};

int
NewMX(struct mxlist *p, int prio, char *host)
{
    if (p->count >= p->size) {
	p->size += 10;
	p->host = p->host ? realloc(p->host, p->size * sizeof(struct mx) )
			  : malloc( p->size * sizeof(struct mx) );
    }

    if (p->host == 0) {
	p->count = p->size = 0;
	return 0;
    }

    p->host[p->count].priority = prio;
    p->host[p->count].name = host;
    return ++p->count;
}

static int
NewIP(struct iplist *p, int key, struct in_addr *addr)
{
    if (p->count >= p->size)
	p->a = p->a ? realloc(p->a, (p->size += 10) * sizeof(struct ipa) )
		    : malloc( (p->size=10) * sizeof(struct ipa) );

    if (p->a == 0) {
	p->count = p->size = 0;
	return 0;
    }

    p->a[p->count].key  = key;
    p->a[p->count].addr = *addr;
    return ++p->count;
}


static char *dn_text  = 0;
static int   dn_alloc = 0;
static int   dn_len   = 0;


static unsigned char *
segment(DNS_REC *rec, unsigned char *p, unsigned int size, unsigned char *end)
{
    if (p < rec->data || p+size > end || p+size > rec->eod)
	return 0;

    if (dn_text == 0 && (dn_text = malloc(dn_alloc=200)) == 0 )
	return 0;

    if (dn_len + size + 1 > dn_alloc)
	if ( (dn_text = realloc(dn_text, dn_alloc += 257)) == 0 )
	    return 0;

    memcpy(dn_text+dn_len, p, size);
    dn_len += size;
    dn_text[dn_len++] = '.';
    dn_text[dn_len] = 0;
    return p + size;
}


static int
backreference(DNS_REC *rec, int offset)
{
    unsigned char size;
    unsigned char *p = offset + (unsigned char*)&(rec->h);

    while (size = *p++) {
	if ( (size & 192) == 192 ) {
	    unsigned short z = (size & ~192) << 8;
	    z |= *p++;

	    return backreference(rec, z);
	}
	else if ( (p = segment(rec, p, size, rec->eod)) == 0)
	    return 0;
    }
    return 1;
}


static unsigned char *
dname(char **np, DNS_REC *rec, unsigned char *p, unsigned char *end)
{
    unsigned char size;

    if (p < rec->data)
	return 0;

    dn_len = 0;

    while ( (size = *p++) ) {

	if ( (size & 192) == 192) {
	    unsigned short z = (size & ~192) << 8;
	    z |= *p++;

	    if ( backreference( rec, z ) ) {
		if (np) *np = dn_text;
		return p;
	    }
	    return 0;
	}
	else if ( (p = segment(rec, p, size, end)) == 0)
	    return 0;
    }
    if (np) *np = dn_text;
    return p;
}


static char *
query(char *host, short qtype, DNS_REC *dp)
{
    char *p;
    int size;
    short rtype, rclass;
    int rc;
    char *name;

    dp->eod = (char*)(&dp->h);

   size = res_query(host, C_IN, qtype, (char*)(&dp->h), dp->alloc);
    if (size < sizeof(HEADER))
	return 0;

    dp->eod = size + (char*)(&dp->h);

    if (dp->h.tc || (dp->h.rcode != 0) )
	return 0;

    if (ntohs(dp->h.qdcount) != 1 || ntohs(dp->h.ancount) < 1)
	return 0;

    /*
     * make certain this is the reply to the correct question
     */
    if ( (p = dname(&name, dp, dp->data, dp->eod)) == 0)
	return 0;

    rc = strcasecmp(host, name);

    GETSHORT(rtype, p);
    GETSHORT(rclass, p);

    if (rc != 0 || rclass != C_IN || rtype != qtype)	/* wrong answer */
	return 0;

    return p;
}


static DNS_REC dns_rec = { 0, sizeof(HEADER)+DDATASZ };

static char *
cname(char *host)
{
    char *name;
    short dclass, dtype;
    long dttl;
    short reclen;
    char *p;

    name = host;

    while (p = query(name, T_CNAME, &dns_rec)) {
	p = dname(0, &dns_rec, p, dns_rec.eod);

	p += 8;
	GETSHORT(reclen, p);

	p = dname(&name, &dns_rec, p, p+reclen);
    }
    return strdup(name);
}

char *
ptr(struct in_addr *ip)
{
    char *name;
    short dclass, dtype;
    long dttl;
    short reclen;
    char *p, *q;
    char candidate[100];
    int i;

    if (ip == 0)
	return 0;

    q = inet_ntoa(*ip);

    candidate[0] = 0;

    while (p = strrchr(q, '.')) {
	*p++ = 0;
	strcat(candidate, p);
	strcat(candidate, ".");
    }
    strcat(candidate, q);
    strcat(candidate, ".in-addr.arpa.");

    if ( (name = cname(candidate)) == 0) name = candidate;

    if (p = query(name, T_PTR, &dns_rec)) {
	p = dname(0, &dns_rec, p, dns_rec.eod);

	p += 8;
	GETSHORT(reclen, p);

	dname(&name, &dns_rec, p, p+reclen);
	if ( name && (0 <= (i = strlen(name)-1)) )
	    if (name[i] == '.')
		name[i] = 0;
	return name;
    }
    return 0;
}


static void
mx(char *host, struct mxlist *list)
{

    char *name;
    char *p;
    int   count, reclen;
    short prio;
    int   i;


    if (p = query(host, T_MX, &dns_rec)) {
	count = ntohs(dns_rec.h.ancount);

	while ( p && (count-- > 0) ) {
	    if ( (p = dname(0, &dns_rec, p, dns_rec.eod)) == 0)
		return;
	    p += 8;

	    GETSHORT(reclen, p);
	    GETSHORT(prio, p);
	    p = dname(&name, &dns_rec, p, p + (reclen-sizeof(prio)) );

	    NewMX(list, prio, strdup(name));
	}
    }
}


static void
address(struct iplist *list, int key, char* host, int allow_localhost)
{
    char *p;
    int count;
    short reclen;
    int i;

    if (p = query(host, T_A, &dns_rec)) {
	count = ntohs(dns_rec.h.ancount);

	while ( p && (count-- > 0) ) {
	    if ( (p = dname(0, &dns_rec, p, dns_rec.eod)) == 0 )
		return;
	    p += 8;
	    GETSHORT(reclen, p);

	    if ( allow_localhost || (memcmp(localhost, p, reclen) != 0) ) {
		for (i=0; i<list->count; i++)
		    if (memcmp( &(list->a[i].addr), p, reclen) == 0)
			break;

		if (i < list->count) {
		    if (list->a[i].key < key)
			list->a[i].key = key;
		}
		else
		    NewIP(list, key, (struct in_addr*)p);
	    }
	    p += reclen;
	}
    }
}


static void
addresslist(struct iplist *list, struct mxlist *mx)
{
    int i;

    for (i=0; i < mx->count; i++)
	address(list, mx->host[i].priority, mx->host[i].name, 0);
}


int
getIPa(char *host, struct iplist *ipp)
{
    char *fqn, *p;
    struct in_addr ipa;

    memset(ipp, 0, sizeof *ipp);

    if ( *host == 0 || (fqn = malloc(strlen(host)+2)) == 0)
	return 0;

    strcpy(fqn, host);
    p = fqn + strlen(fqn);

    if ( (*fqn == '[') && (p[-1] == ']') ) {
	long int ip;

	p[-1] = 0;
	if ( (ip = inet_addr(1+fqn)) != -1) {
	    ipa = inet_makeaddr(ntohl(ip), 0L);
	    NewIP(ipp, 0, &ipa);
	}
    }
    else {
	/*_res.options |= RES_USEVC|RES_STAYOPEN;*/
	if ( !(_res.options & RES_INIT) )
	    res_init();

	if (p[-1] != '.') {
	    *p++ = '.';
	    *p = 0;
	}
	address(ipp, 0, fqn, 1);
    }
    free(fqn);
    return ipp->count;
}


static int
cmp(struct ipa *a, struct ipa *b)
{
    return b->key - a->key;
}


static void
freemxlist(struct mxlist *p)
{
    int i;

    for (i=0; i < p->count; i++)
	free(p->host[i].name);
    free(p->host);
    p->size = p->count = 0;
    p->host = 0;
}


void
freeiplist(struct iplist *p)
{
    int i;

    free(p->a);
    p->size = p->count = 0;
    p->a = 0;
}


int
getMXes(char *host, struct iplist *ipp)
{
    struct mxlist list = { 0 };
    char *candidate;
    char *fq;
    char *wildcard;
    int i;
    static struct in_addr localhost_buffer;
    struct in_addr ipa;

    memset(ipp, 0, sizeof *ipp);

    if (localhost == 0) {
	localhost_buffer = inet_makeaddr(ntohl(inet_addr("127.0.0.1")), 0L);
	localhost = &localhost_buffer;
    }

    if ( (candidate = malloc((i=strlen(host))+2)) == 0)
	return -1;
    strcpy(candidate, host);

    if (*candidate == '[') {		/* [xxx.xxx.xxx.xxx] -> IP address */
	long int ip;

	if ( *(fq = candidate + strlen(candidate)-1) == ']') {
	    *fq = 0;
	    if ( (ip = inet_addr(1+candidate)) != -1)
		ipa = inet_makeaddr(ntohl(ip), 0L);
		NewIP(ipp, 0, &ipa);
	}
	free(candidate);

	return ipp->count;
    }

    /*_res.options |= RES_USEVC|RES_STAYOPEN;*/
    if ( !(_res.options & RES_INIT) )
	res_init();

    if (i > 0 && candidate[i-1] != '.') {
	candidate[i] = '.';
	candidate[i+1] = 0;
    }

    /* first resolve cnames */
    fq = cname(candidate);

    free(candidate);

    if (fq == 0)
	return -1;

    /* then find the MXes for the new host */
    mx(fq, &list);

    if (list.count < 1) {
	/* if that fails, try the MXes for the wildcard host */
	if ( wildcard = malloc(strlen(fq)+5) ) {
	    sprintf(wildcard, "*.%s", fq);
	    mx(wildcard, &list);
	    free(wildcard);
	}
	else {
	    free(candidate);
	    free(fq);
	    return -1;
	}
    }

    if (list.count < 1) {
	/* if THAT fails, just use the A address for the host */
	address(ipp, 0, fq, 1);
    }
    else {
	free(fq);
	addresslist(ipp, &list);
    }
    freemxlist(&list);
    qsort(ipp->a, ipp->count, sizeof ipp->a[0], cmp);
    return ipp->count;
} /* getMX */


#ifdef DEBUG

main(int argc, char **argv)
{
    char candidate[100];
    char *host;
    char *wildcard;
    struct iplist hosts = { 0 };
    unsigned long ip_addr;
    int i;
    struct in_addr ip;

    if (argc <= 1) {
	fprintf(stderr, "usage: mx host-name\n");
	exit(1);
    }

    if (strcmp(argv[1], "ptr") == 0) {
	ip_addr = inet_addr(argv[2]);
	if (ip_addr == -1)
	    printf("%s is unresolvable.\n", argv[2]);
	else {
	    ip = inet_makeaddr(htonl(ip_addr), 0L);
	    host = ptr(&ip);
	    printf("%s -> %s\n", argv[2], host ? host : "NIL");
	}
    }
    else {
	getMXes(argv[1], &hosts);

	for (i=0; i < hosts.count; i++)
	    printf("%d\t%s\n", hosts.a[i].key, inet_ntoa(hosts.a[i].addr));
    }
}

#endif
