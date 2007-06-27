#ifndef __MBOX_D
#define __MBOX_D

#include "env.h"

struct mbox {
    FILE *in;
    FILE *out;
    FILE *log;
    struct in_addr ip;
    int fd;
    long size;		/* maximum messagesize or 0 */
    int esmtp : 1;
    int sizeok : 1;	/* saw SIZE in ehlo reply */
    int verbose : 1;
    int opened : 1;
} ;


typedef struct mbox MBOX;

extern MBOX *newmbox(struct in_addr *, int, int);
extern MBOX *freembox(MBOX *);

extern char *readmbox(MBOX *);
extern int  writembox(MBOX *, char *, ...);
extern int  reply(MBOX*, void (*f)(MBOX*,char*));


struct mbox_cache {
    MBOX *session;	/* a mailbox */
    char *host;		/* domain this session is for */
    struct in_addr mx;	/* mx this session is attached to */
    int prio;		/* how recently has it been used? */
} ;

extern MBOX *session(ENV *, char *, int);
extern void close_sessions();

#endif/*__MBOX_D*/
