#ifndef _DOMAIN_D
#define _DOMAIN_D

#include <pwd.h>
#include <sys/types.h>

struct domain {
    char *domain;		/* the domain name */
    int   vhost;		/* is this a virtual host? */

    char *mailbox;		/* mailbox template */
    char *userptr;		/* where to point the user at */
    char *passwd;		/* /etc/passwd for this domain */
    char *aliases;		/* /etc/aliases for this domain */

    uid_t d_uid;		/* uid of vhost owner */
    gid_t d_gid;		/* gid " " " */
};

struct domain* getdomain(char*);
int            isvhost(struct domain*);
char*          mailbox(struct domain*, char*);
char*          passwdfile(struct domain*);
char*          aliasfile(struct domain*);
char*          username(struct domain*, char*);

int initdomain();

struct passwd *getvpwemail(struct domain *dom, char* user);

#endif/*_DOMAIN_D*/
