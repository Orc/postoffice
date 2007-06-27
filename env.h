#ifndef ENV_D
#define ENV_D

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct env {
    struct in_addr *local_if;	/* ip addresses assigned to the local machine */
    char *localhost;		/* name of localhost */
    unsigned long largest;	/* longest message we accept */
    float max_loadavg;		/* if la > this, don't accept mail */
    char *argv0;		/* argv0, for status scribbling */
    int   max_clients;		/* max# of connections allowed */
    int   max_hops;		/* max# of received-by: headers */
    int   timeout;		/* how long to wait for input */
    char  bmode;
    uid_t sender;		/* user who called postoffice */
    int   delay;		/* greylist delay */
    int   qreturn;		/* how long to leave mail in the queue? */
    unsigned int   nodaemon:1;	/* refuse MAIL FROM:<> */
    unsigned int   verbose:1;	/* be chattery */
    unsigned int   paranoid:1;	/* don't accept email from clients we can't
				 * resolve */
    unsigned int   doublecheck:1;/* resolve caller IP->name, then name->IP */
    unsigned int   relay_ok:1;	/* Is it okay to mail to remote machines? */
    unsigned int   debug:1;	/* enable debugging commands */
    unsigned int   forged:1;	/* from address set by -f */
    unsigned int   trawl:1;	/* scrape headers for recipients (pine sucks) */
    unsigned int   checkhelo:1;	/* verify HELO/EHLO header */
    unsigned int   localmx:1;	/* if I am the mx for a client, that
				 * client can relay.  DANGEROUS!  */
} ;

typedef struct env ENV;


char *mapfd(int, size_t*);

void set_option(char *, ENV*);
int  configfile(char *, ENV*);
void message(FILE *f, int code, char *fmt, ...);


#endif/*END_D*/