#ifndef PUBLIC_D
#define PUBLIC_D

#include <sys/types.h>
#include <dirent.h>

#include "config.h"
#include "letter.h"

/* getloadavg.c */
#ifndef HAVE_GETLOADAVG
int getloadavg(double *, int);
#endif

/* config.c */
int value(char *, int *, char *);
void myname(ENV *);

/* goodness.c */
int goodness(struct letter *, int);


/* greylist.c */
int greylist(struct letter *, int);

/* listq.c */
int Qpicker(const struct dirent *);
void listq();

/* local.c */
int runlocal(struct letter *);

/* mail.c */
int addto(struct letter *, char *);
void mail(char *, int, char **, ENV *);

/* mbox.c */
void close_sessions();

/* newaliases.c */
void newaliases(int, char **);

/* remote.c */
void forward(struct letter *);


/* runq.c */
void runjob(struct letter *, char *);
int runlock();
void rununlock();
int runq(struct env *);

/* server.c */
#ifndef HAVE_SETPROCTITLE
void setproctitle(const char *, ...);
#endif
int islocalhost(ENV *, struct in_addr *);
void daemonize(ENV *, int);
void server(ENV *, int);
void runqd(ENV *, int);

/* userok.c */
int userok(struct letter *, struct address *);

/* virusscan.c */
int virus_scan(struct letter *);

/* locker.c */
int locker(int, int);

#endif/*PUBLIC_D*/
