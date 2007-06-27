#ifndef __LETTER_D
#define __LETTER_D

#include <stdio.h>
#include <pwd.h>
#include <sys/types.h>

#include "env.h"
#include "domain.h"

struct address {
    char *full;			/* full address <blah@blah> or <blah!blah> */
    char *domain;		/* domain we want to send it to */
    char *user;			/* user at that domain */
    char *alias;		/* (or alias in /etc/aliases) */
    int   local;		/* is this a local address? */
    struct domain *dom;		/* local mail domain */
} ;

struct email {
    char *user;			/* username (from passwd/vpasswd) */
    char *domain;		/* domain (from struct address*) */
    char *forward;		/* contents of .forward file (real user) */
    uid_t uid;			/* their userid */
    gid_t gid;			/*  and groupid */
    struct domain *dom;		/* local mail domain */
} ;

struct recipient {
    enum r_type { emALIAS, emFILE, emEXE, emUSER } typ;
    enum r_status { FAILED=0, PENDING, MAILED } status;
    char *fullname;
    char *user;
    char *host;
    uid_t uid;
    gid_t gid;
    struct domain *dom;
};

struct list {
    struct recipient *to;
    int count;
    int size;
};


struct letter {
    struct address *from;	/* mail from: */
    struct list local;		/* (expanded) local recipients */
    struct list remote;		/* (expanded) remote recipients */

    char  *deliveredby;		/* machine doing the delivery */
    char  *deliveredIP;		/* IP address for that machine */
    char  *deliveredto;		/* machine being delivered to */
    FILE  *body;		/* the mail message */
    char  *bodytext;		/* mmap()ed copy of the body */
    size_t bodysize;		/* # bytes in it */
    char  *headtext;		/* malloc()ed copy of extra headers */
    size_t headsize;		/* size of extra headers */
    char   qid[8];		/* spool file suffix */
    char  *tempfile;		/* temporary spoolfile */
    FILE  *in, *out;		/* data connection */
    ENV   *env;		/* global env pointer */
    time_t posted;		/* when was this letter written? */
    FILE  *log;			/* messages generated during mail posting */
    int    hopcount;		/* # of Received: lines in message */
    int    status;		/* subprocess status during local delivery */
    char  *qcomment;		/* qfile comment for remote delivery */
    unsigned int fatal:1;	/* a fatal error has occurred; time to die */
    unsigned int helo:1;	/* did the mailman say HELO? */
    unsigned int has_headers:1;	/* does the message already contain headers? */
    unsigned int date:1;	/* in particular, does it contain a date:? */
    unsigned int messageid:1;	/*                        or a messageid:? */
    unsigned int mesgfrom:1;	/*			       or a from:? */
    unsigned int mboxfrom:1;	/* Is the first header line ``From ...'' */
} ;

int prepare(struct letter *, FILE *, FILE *, ENV *);
void reset(struct letter *);
void byebye(struct letter *, int);

char *lowercase(char *);
char *skipspace(char *);
struct email *getemail(struct address *);


/* verify failure reasons */
#define V_NOMX	1
#define V_WRONG 2
#define V_BOGUS	3
#define V_ERROR	4

/* verify options */
#define VF_USER	0x01
#define VF_FROM	0x02

extern struct address* verify(struct letter*, struct domain*, char*, int, int*);
extern void freeaddress(struct address*);

extern int newrecipient(struct list*, struct address*, enum r_type,uid_t,gid_t);
extern int recipients(struct letter*, struct address*);

#endif/*__LETTER_D*/
