/*
 * set configuration options (from the command line or a file)
 */
#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>

#include <syslog.h>
#include <sysexits.h>

#include "env.h"
#include "audit.h"
#ifdef WITH_MILTER
#include "mf.h"
#endif
#include "public.h"


int
value(char *p, int *val, char *m)
{
    char *ep;
    int   units;

    *val = strtol(p, &ep, 10);

    if (ep == p)
	return 0;

    if (*ep && m) {
	while (m = strchr(m+1,'='))
	    if (m[-1] == tolower(*ep)) {
		if ( (units = atoi(m+1)) > 0 )
		    (*val) *= units;
		return 1;
	    }
    }
    return 1;
}


static int
isopt(char *arg, char *opt, int *val, char *m)
{
    int   olen = strlen(opt);
    char *p    = arg + olen;

    if (strncmp(arg, opt, olen) == 0) {
	if (*p == '=')
	    return value(p+1, val, m);
	else if (*p == 0) {
	   *val = 1;
	   return 1;
	}
    }
    return 0;
}


static void
insecure(char *what)
{
    extern char *pgm;

    if (getuid() == 0)
	return;
    fprintf(stderr, "%s: You may not set %s.\n", pgm, what);
    syslog(LOG_CRIT, "User #%d attempted to set %s", getuid(), what);
    exit(EX_NOPERM);
}


static void
not_a_secure_cf(char *what, char *why, char *cf)
{
    extern char *pgm;

    if (what) {
	int siz = strlen(what);

	fprintf(stderr, "%s: [%.*s]%s is not a secure path: %s.\n",
				    pgm, siz, what, cf+siz, why);
	syslog(LOG_CRIT, "config file [%.*s]%s is not a secure path: %s",
					 siz, what, cf+siz, why);
    }
    else {
	fprintf(stderr, "%s: %s is not secure: %s.\n", pgm, cf, why);
	syslog(LOG_CRIT, "config file %s is not secure: %s", cf, why);
    }
    exit(EX_OSFILE);
}


int
configfile(int super, char *cf, ENV *env)
{
    char line[200];
    FILE *f;
    char *p;
    struct stat sb;

    if (super) {
	/* verify that the config file is a file, is owned by
	 * root, is not world writable, and is in a path that
	 * is owned by root and which is not world writable.
	 */
	 /* first check the file */
	if ( cf[0] != '/' )
	    not_a_secure_cf(0, "not /", cf);
	if ( strlen(cf) >= sizeof line )
	    not_a_secure_cf(0, "too long", cf);
	if ( stat(cf, &sb) != 0 )
	    not_a_secure_cf(0, "can't stat", cf);
	if ( sb.st_uid != 0 )
	    not_a_secure_cf(0, "not owner 0", cf);
	if ( sb.st_gid != 0 )
	    not_a_secure_cf(0, "not group 0", cf);
	if ( !S_ISREG(sb.st_mode) )
	    not_a_secure_cf(0, "not a file", cf);
	if ( sb.st_mode & S_IWOTH )
	    not_a_secure_cf(0, "world writable", cf);

#if 0
	if ( cf[0] != '/' || strlen(cf) >= sizeof line
			  || stat(cf, &sb) != 0
			  || sb.st_uid != 0 || sb.st_gid != 0
			  || !S_ISREG(sb.st_mode)
			  || (sb.st_mode&S_IWOTH) )
	    not_a_secure_cf(0, cf);
#endif

	 /* then check each part of the path */
	 strcpy(line, cf);
	 while ( (p = strrchr(line, '/')) ) {
	    char *elem;
	    *p = 0;

	    elem = line[0] ? line : "/";

	    if ( stat(elem, &sb) != 0 )
		not_a_secure_cf(elem, "can't stat", cf);
	    if ( sb.st_uid != 0 )
		not_a_secure_cf(elem, "not owner 0", cf);
	    if ( sb.st_gid != 0 )
		not_a_secure_cf(elem, "not group 0", cf);
	    if ( !S_ISDIR(sb.st_mode) )
		not_a_secure_cf(elem, "not a directory", cf);
	    if ( sb.st_mode & S_IWOTH )
		not_a_secure_cf(elem, "world writable", cf);

#if 0
	    if ( stat(line[0] ? line : "/", &sb) != 0 || sb.st_uid != 0
						      || sb.st_gid != 0
						      || !S_ISDIR(sb.st_mode)
						      || (sb.st_mode&S_IWOTH) )
		not_a_secure_cf(line[0] ? line : "/", cf);
#endif
	 }
    }


    if (f = fopen(cf, "r")) {
	while (fgets(line, sizeof line, f)) {
	    if (p = strchr(line, '#')) 
		*p = 0;

	    p = &line[strlen(line)-1];
	    while ( (p >= line) && isspace(*p) )
		*p-- = 0;

	    if (line[0])
		set_option(super, line, env);
	}
	fclose(f);
	return 1;
    }
    return 0;
}


void
dealwithspam(int super, char *option, int offset, struct spam *ret)
{
    char *p, *cmd = option;

    if (p = strchr(option, ':'))
	*p++ = 0;

    if (!super) insecure(option);
    
    option += offset;
    if (strcasecmp(option, "bounce")  == 0) {
	ret->action = spBOUNCE;
	if (p && *p) {
	    if (ret->reason)
		free(ret->reason);
	    ret->reason = strdup(p);
	}
    }
    else if (strcasecmp(option, "accept") == 0) {
	if (!super) insecure(cmd);
	ret->action = spACCEPT;
    }
    else if (strcasecmp(option, "folder") == 0) {
	if (p == 0 || *p == 0) {
	    fprintf(stderr, "need a destination file for %s config\n", cmd);
	    syslog(LOG_INFO, "need a destination file for %s config", cmd);
	}
	else if ( (strncmp(p, "~/", 2) == 0) || (strchr(p, '/') == 0) ) {
	    if (ret->folder)
		free(ret->folder);
	    ret->folder = strdup(p);
	    ret->action = spFILE;
	}
	else {
	    fprintf(stderr, "malformed %s path (%s)\n", cmd, p);
	    syslog(LOG_INFO, "malformed %s path (%s)", cmd, p);
	}
    }
    else {
	fprintf(stderr, "unknown action %s\n", cmd);
	syslog(LOG_INFO, "unknown action %s\n", cmd);
    }
}


void
set_option(int super, char *option, ENV *env)
{
    int val;

    switch (option[0]) {
    case 'a':	if (isopt(option, "audit", &val, 0))
		    env->auditing = val;
		return;
    case 'b':   if (strncmp(option, "blacklist=", 10) == 0)
		    dealwithspam(super, option, 10, &(env->rej) );
		return;
    case 'c':   if (isopt(option, "checkhelo", &val, 0))
		    env->checkhelo = val;
		isopt(option, "clients", &env->max_clients, 0);
		return;
    case 'd':   if (isopt(option, "dnscheck", &val, 0))
		    env->doublecheck = val;
		else if (isopt(option, "debug", &val, 0))
		    env->debug = val;
		else 
		    isopt(option, "delay", &env->delay, "m=60,h=3600,d=86400");
		return;
    case 'e':	if (isopt(option, "escape-from", &val, 0))
		    env->escape_from = val;
		return;
    case 'f':   if (isopt(option, "forward-all", &val, 0)) {
		    if (!super) insecure("forward-all");
		    env->forward_all = val;
		}
#ifdef WITH_MILTER
		else if (strncasecmp(option, "filter=", 7) == 0)
		    mfregister(option+7,0);
#endif
		return;
    case 'h':	isopt(option,"hops", &env->max_hops, 0);
		return;
    case 'i':	if (isopt(option, "immediate", &val, 0))
		    env->immediate = val;
		return;
    case 'l':   if (isopt(option, "load", &val, 0))
		    env->max_loadavg = (float)val;
		else if (isopt(option, "localmx", &val, 0))
		    env->localmx = val;
		return;
#if HAVE_STATFS || HAVE_STATVFS
    case 'm':   if (isopt(option, "minfree", &val, "m=1000,g=1000000"))
		    env->minfree = val * 1024;
		return;
#endif
    case 'n':   if (isopt(option, "nodaemon", &val, 0))
		    env->nodaemon = val;
		return;
    case 'p':   if (isopt(option, "paranoid", &val, 0))
		    env->paranoid = val;
		return;
    case 'q':	isopt(option, "qreturn", &env->qreturn, "m=60,h=3600,d=86400");
		return;
    case 'r':   if (isopt(option, "relay", &val, 0))
		    env->relay_ok = val;
		else if (strncasecmp(option, "relay-host=", 11) == 0) {
		    if (!super) insecure("relay-host");
		    if (env->relay_host)
			free(env->relay_host);
		    env->relay_host = strdup(option+11);
		}
		return;
    case 's':   if (isopt(option, "size", &val, "k=1000,m=1000000"))
		    env->largest = val;
		else if (strncasecmp(option, "self=", 5) == 0) {
		    if (env->localhost)
			free(env->localhost);
		    env->localhost = strdup(option+5);
		}
		else if (strncasecmp(option, "spam=", 5) == 0)
		    dealwithspam(super, option, 5, &(env->spam));
		return;
    case 't':   if (strncasecmp(option,"trusted=",8) == 0) {
		    if (!super) insecure("trusted");
		    getIPa(option+8, 0, &env->trusted);
		}
		else 
		    isopt(option,"timeout",&env->timeout,"m=60,h=3600,d=86400");
		return;
    case 'u':   if (strncasecmp(option, "usermap=", 8) == 0) {
		    struct usermap *tmp, *t;
		    char *q;

		    if ( tmp = malloc(sizeof tmp[0] + strlen(option)) ) {
			tmp->pat = strdup(option+8);
			if ( (q = strchr(tmp->pat, ':')) ) {
			    *q++ = 0;

			    tmp->map = q;
			    tmp->next = 0;

			    if (env->usermap) {
				for (t=env->usermap;t->next; t=t->next)
				    ;
				t->next = tmp;
			    }
			    else
				env->usermap = tmp;
			}
			else	/* silently ignore null maps */
			    free(tmp);
		    }
		}
		return;
    case 'v':   if (isopt(option, "verify-from", &val, 0))
		    env->verify_from = val;
		return;
    }
    /* complain if I want to */
}
