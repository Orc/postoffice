/*
 * set configuration options (from the command line or a file)
 */
#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <syslog.h>
#include <sysexits.h>

#include "env.h"


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


void
set_option(char *option, ENV *env)
{
    int val;

    switch (option[0]) {
    case 'a':	if (isopt(option, "audit", &val, 0))
		    env->auditing = val;
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
		    insecure("forward-all");
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
		    insecure("relay-host");
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
		else if (isopt(option, "soft-deny", &val, 0))
		    env->soft_deny = val;
		return;
    case 't':   isopt(option,"timeout", &env->timeout,"m=60,h=3600,d=86400");
		return;
    case 'v':   if (isopt(option, "verify-from", &val, 0))
		    env->verify_from = val;
		return;
    }
    /* complain if I want to */
}


int
configfile(char *cf, ENV *env)
{
    char line[200];
    FILE *f;
    char *p;

    if (f = fopen(cf, "r")) {
	while (fgets(line, sizeof line, f)) {
	    if (p = strchr(line, '#')) 
		*p = 0;

	    p = &line[strlen(line)-1];
	    while ( (p >= line) && isspace(*p) )
		*p-- = 0;

	    if (line[0])
		set_option(line, env);
	}
	fclose(f);
	return 1;
    }
    return 0;
}
