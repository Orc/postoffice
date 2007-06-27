#include "config.h"

#include <stdio.h>
#if OS_FREEBSD
#   include <stdlib.h>
#else
#   include <malloc.h>
#endif
#include <pwd.h>
#include <sys/types.h>
#include <string.h>
#include <syslog.h>
#include <paths.h>

#include "letter.h"
#include "domain.h"


static struct domain *domains = 0;
static int nrdom = 0;


static int
add_dom(char *domain, char *user, char *spool, char *etc)
{
    int a, b, size;
    struct passwd *pwd;
    struct domain *p;

    if (user && ((pwd = getpwnam(user)) == 0) ) {
	syslog(LOG_ERR, "virtual domain %s owned by %s: %m", domain, user);
	return 1;	/* successfully added nothing */
    }

    if ( (domains = realloc(domains, (1+nrdom)*sizeof domains[0])) == 0 )
	return 0;

    p = &domains[nrdom];
    p->domain = domain ? strdup(domain) : 0;

    if (domain && (p->domain == 0) )
	return 0;

    a = strlen(spool);
    b = strlen(etc);
    size = ((a>b) ? a : b) + 1 + MAX_USERLEN + 1;
    if (domain)
	size += strlen(domain) + 1;

    if ( (p->mailbox = malloc(3 * size)) == 0)
	return 0;

    p->passwd = p->mailbox + size;
    p->aliases = p->passwd + size;

    if (domain) {
	sprintf(p->mailbox, "%s/%s/", spool, domain);
	sprintf(p->passwd, "%s/%s/passwd", etc, domain);
	sprintf(p->aliases, "%s/%s/aliases", etc, domain);
	p->vhost = 1;
	p->d_uid = pwd->pw_uid;
	p->d_gid = pwd->pw_gid;
    }
    else {
	sprintf(p->mailbox, "%s/", spool);
	sprintf(p->passwd, "%s/passwd", etc);
	sprintf(p->aliases, "%s/aliases", etc);
	p->vhost = 0;
    }
    p->userptr = p->mailbox + strlen(p->mailbox);
    nrdom++;
    return 1;
}


int
initdomain()
{
    FILE *f;
    int size;

    if (domains) return 1;


    add_dom(0, 0, _PATH_MAILDIR, "/etc");

#ifdef VPATH
    if ( f = fopen(VPATH "/domains.cf", "r") ) {
	char bfr[200];
	char *owner, *domain, *active;
	struct passwd *pwd;

	while (fgets(bfr, sizeof bfr, f)) {
	    owner = strtok(bfr, ":");
	    domain = strtok(0, ":");
	    active = strtok(0, ":");

	    if (owner && domain && active)
		add_dom(domain,owner,VSPOOL,VPATH);
	}
	fclose(f);
	return 1;
    }
#endif
    return 0;

}


struct domain *
getdomain(char *dom)
{
    int i;

    initdomain();

    if (dom == 0) return domains + 0;

    for (i=1; i < nrdom; i++)
	if (strcasecmp(dom, domains[i].domain) == 0)
	    return domains + i;

    return (struct domain*)0;
}


int
isvhost(struct domain *p)
{
    return p && p->vhost;
}


char *
mailbox(struct domain *dom, char *user)
{
    if (dom == 0)
	dom = getdomain(0);

    if ( user && (strlen(user) < MAX_USERLEN) && (strchr(user, '/') == 0) ) {
	strcpy(dom->userptr, user);
	return dom->mailbox;
    }
    return 0;
}


char *
passwdfile(struct domain *dom)
{
    if (dom == 0)
	dom = getdomain(0);

    return dom->passwd;
}

char *
aliasfile(struct domain *dom)
{
    if (dom == 0)
	dom = getdomain(0);

    return dom->aliases;
}

struct passwd *
getvpwemail(struct domain *dom, char* user)
{
    char *thisuser;
    FILE *f;
    char bfr[200];
    static struct passwd ent;

    if (dom == 0 || dom->vhost == 0)	/* only works on virtual hosts */
	return 0;

    if ( (f = fopen(dom->passwd, "r")) != 0 ) {
	while (fgets(bfr, sizeof bfr, f)) {
	    thisuser = strtok(bfr, ":");
	    if (thisuser && (strcasecmp(user, thisuser) == 0) ) {
		ent.pw_name = user;
		ent.pw_uid  = dom->d_uid;
		ent.pw_gid  = dom->d_gid;
		fclose(f);
		return &ent;
	    }
	}
	fclose(f);
    }
    return 0;
}
