/*
 * set configuration options (from the command line or a file)
 */
#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "env.h"


static int
isopt(char *arg, char *opt, int *val, char *m)
{
    int   olen = strlen(opt);
    char *p    = arg + olen;
    char *ep;
    int   units;

    if (strncmp(arg, opt, olen) == 0) {
	if (*p == '=') {
	    *val = strtol(p+1, &ep, 10);
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
	else if (*p == 0) {
	   *val = 1;
	   return 1;
	}
    }
    return 0;
}


void
set_option(char *option, ENV *env)
{
    int val;

    switch (option[0]) {
    case 'c':   if (isopt(option, "checkhelo", &val, 0))
		    env->checkhelo = val;
		isopt(option, "clients", &env->max_clients, 0);
		return;
    case 'p':   if (isopt(option, "paranoid", &val, 0))
		    env->paranoid = val;
		return;
    case 'r':   if (isopt(option, "relay", &val, 0))
		    env->relay_ok = val;
		return;
    case 'h':	isopt(option,"hops", &env->max_hops, 0);
		return;
    case 'q':	isopt(option, "qreturn", &env->qreturn, "m=60,h=3600,d=86400");
		return;
    case 's':   if (isopt(option, "size", &val, "k=1000,m=1000000"))
		    env->largest = val;
		return;
    case 'd':   if (isopt(option, "dnscheck", &val, 0))
		    env->doublecheck = val;
		else if (isopt(option, "debug", &val, 0))
		    env->debug = val;
		else 
		    isopt(option, "delay", &env->delay, "m=60,h=3600,d=86400");
		return;
    case 'n':   if (isopt(option, "nodaemon", &val, 0))
		    env->nodaemon = val;
		return;
    case 't':   isopt(option,"timeout", &env->timeout,"m=60,h=3600,d=86400");
		return;
    case 'l':   if (isopt(option, "load", &val, 0))
		    env->max_loadavg = (float)val;
		else if (isopt(option, "localmx", &val, 0))
		    env->localmx = val;
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
	    if (p = strchr(line, '\n')) 
		*p = 0;
	    set_option(line, env);
	}
	fclose(f);
	return 1;
    }
    return 0;
}