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

#include "letter.h"

struct vhost {
    char *domain;		/* the domain name */
    char *vspool;		/* the spool directory */
    char *vetc;			/* the passwd/aliases directory */
    uid_t user;			/* uid of vhost owner */
    gid_t group;		/* gid " " " */
};

static struct vhost* vhosts = 0;
static int nrvhosts = 0;


static int
readvhosts()
{
    FILE *f;
#ifdef VPATH
    if (vhosts)
	return 1;
    if ( f = fopen(VPATH "/domains.cf", "r") ) {
	char bfr[200];
	char *owner, *domain, *active;
	struct passwd *pwd;

	vhosts = malloc(1);

	while (fgets(bfr, sizeof bfr, f)) {
	    owner = strtok(bfr, ":");
	    domain = strtok(0, ":");
	    active = strtok(0, ":");

	    if (owner && domain && active) {
		if ( (pwd = getpwnam(owner)) == 0) {
		    syslog(LOG_ERR, "readvhosts %s %m", owner);
		    continue;
		}

		vhosts = realloc(vhosts, (1+nrvhosts) * sizeof vhosts[0]);
		if (vhosts == 0) {
	     nomem: nrvhosts = 0;
		    syslog(LOG_ERR, "readvhosts %m");
		    return 0;
		}
		if ( (vhosts[nrvhosts].domain = strdup(domain)) == 0)
		    goto nomem;

		vhosts[nrvhosts].vspool = malloc(sizeof VSPOOL + 1
							       + strlen(domain)
							       + 1);
		if (vhosts[nrvhosts].vspool == 0)
		    goto nomem;

		sprintf(vhosts[nrvhosts].vspool, VSPOOL "/%s", domain);

		vhosts[nrvhosts].vetc = malloc(sizeof VPATH + 1
							    + strlen(domain)
							    + 1);
		if (vhosts[nrvhosts].vetc == 0)
		    goto nomem;
		sprintf(vhosts[nrvhosts].vetc, VPATH "/%s", domain);

		vhosts[nrvhosts].user = pwd->pw_uid;
		vhosts[nrvhosts].group= pwd->pw_gid;
		nrvhosts++;
	    }
	}
	fclose(f);
	return 1;
    }
#endif
    return 0;

}


static int 
vlookup(char *p)
{
    int i;

    if (p == 0) return -1;

    readvhosts();

    for (i=0; i < nrvhosts; i++)
	if (strcasecmp(p, vhosts[i].domain) == 0)
	    return i;

    return -1;
}

char *
isvhost(char *p)
{
    int i = vlookup(p);

    return (i>=0) ? vhosts[i].vetc : 0;
}


char *
vspool(char *p)
{
    int i = vlookup(p);

    return (i >= 0) ? vhosts[i].vspool : 0;
}


struct passwd *
getvpwemail(char* user, char* host)
{
    char *pwdf, *thisuser;
    int  i = vlookup(host);
    FILE *f;
    char bfr[200];
    static struct passwd ent;

    if (i == -1)
	return 0;

    if ( (pwdf=alloca(strlen(vhosts[i].vetc) + sizeof "/passwd" + 1)) == 0)
	return 0;

    sprintf(pwdf, "%s/passwd", vhosts[i].vetc);

    if ( (f = fopen(pwdf, "r")) != 0 ) {
	while (fgets(bfr, sizeof bfr, f)) {
	    thisuser = strtok(bfr, ":");
	    if (thisuser && (strcasecmp(user, thisuser) == 0) ) {
		ent.pw_name = user;
		ent.pw_uid  = vhosts[i].user;
		ent.pw_gid  = vhosts[i].group;
		fclose(f);
		return &ent;
	    }
	}
	fclose(f);
    }
}
