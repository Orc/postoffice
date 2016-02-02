/*
 * smtp gateway server
 */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <sys/utsname.h>
#include <netdb.h>
#include <sysexits.h>

#if HAVE_LIBGEN_H
#include <libgen.h>
#endif

extern char myversion[];

#include "letter.h"
#include "smtp.h"
#include "audit.h"
#include "public.h"


#ifndef HAVE_SETPROCTITLE
char *argv0;
int   szargv0;
#endif


extern int   z_getopt();
extern char* z_optarg;
extern int   z_optind;

void
superpowers()
{
    if (getuid() != geteuid()) {
	/* pick up our superpowers (if any) */
	setuid(geteuid());
	setgid(getegid());
    }
}

char *pgm;

main(int argc, char **argv)
{
    int opt;
    int Cflag = 0;			/* flag for -C */
    extern struct in_addr *local_if_list();
    struct sockaddr_in *peer = 0;	/* peer for -bs (for debugging) */
    static ENV env;
    char *from = 0;
    char *options = "aA:B:C:dF:f:r:b:o:h:R:q;GUVimnv";
    char *modes = "sqpmid";
    struct utsname sys;
    struct hostent *p;
    int debug = 0;
    int sendmaild0 = 0;
    int qruntime = 0;

    env.bmode = 'm';
    env.local_if = local_if_list();
    env.relay_ok = 1;		/* allow local relaying */
    env.verbose = 0;		/* be chattery */
    env.verify_from = 1;	/* verify the host of MAIL FROM:<user@host> */
    env.nodaemon = 0;		/* allow MAIL FROM:<> */
    env.delay = 3600;		/* greylist delay */
    env.largest = 0;
    env.debug = 0;
    env.sender = getuid();
    env.timeout = 300;
    env.qreturn = 86400*3;	/* 3 days */
    env.max_loadavg = 4.0;
#if HAVE_STATFS || HAVE_STATVFS
    env.minfree = 10*1000*1024;	/* 10m free for messages */
#else
    env.minfree = 0;
#endif
    env.max_clients = 100;	/* should be fairly ridiculous */
    env.max_hops = 100;		/* (ditto) */

    env.spam.action = spBOUNCE;
    env.rej.action = spBOUNCE;

    Shuffle;			/* set up the random # generator for mx sorting */

#ifndef HAVE_SETPROCTITLE
    argv0 = argv[0];
    szargv0 = 80;
    /*for (env.szargv0=i=0; i<argc; i++)
	env.szargv0 += strlen(argv[i]) + 1;*/
#endif

    if ( p = gethostbyname((uname(&sys) == 0) ? sys.nodename : "localhost") )
	env.localhost = strdup(p->h_name);
    else
	env.localhost = "localhost";

#if HAVE_BASENAME
    pgm = strdup(basename(argv[0]));
#else
    {   char *avp = strrchr(argv[0], '/');
	pgm = strdup(avp ? avp+1 : argv[0]);
    }
#endif
    openlog(pgm, LOG_PID, LOG_MAIL);

#if 0
    {	int i;
	for (i=0; i < argc; i++)
	    syslog(LOG_INFO, "argv[%d] = %s", i, argv[i]);
    }
#endif

#define SAME(a,b)	(strcasecmp(a,b) == 0)

    /* handle magic program names */
    if ( SAME(pgm, "mailq") ) {
	options = "vA:Vq:";
	env.bmode = 'p';
    }
    else if ( SAME(pgm, "sendmail") || SAME(pgm, "send-mail") ) {
	options = "A:b:d;F:f:imo:r:q;Vvt";
	env.bmode = 'm';
    }
    else if ( SAME(pgm, "runq") ) {
	options = "o:Vv";
	env.bmode = 'q';
    }
    else if ( SAME(pgm, "newaliases") ) {
	options = "vV";
	env.bmode = 'i';
    }
    else if ( SAME(pgm, "smtpd") ) {
	options = "aA:B:C:do:h:q:R:GUmnvV";
	env.bmode = 'd';
    }

    while ( (opt = z_getopt(argc, argv, options)) != EOF) {
	switch (opt) {
	case 'a':
		env.auditing = 1;
		break;
	case 'A':/*ignored*/
		break;
	case 'C':
		Cflag = 1;
		if (configfile( 0, z_optarg, &env ) == 0) {
		    perror(z_optarg);
		    exit(EX_NOINPUT);
		}
		break;
	case 'R':
#ifdef USE_PEER_FLAG
		{   struct sockaddr_in fake;
		    long ip;

		    if ( (ip = inet_addr(z_optarg)) != -1) {
			fake.sin_addr = inet_makeaddr(ntohl(ip), 0L);
			fake.sin_family = AF_INET;
			peer = &fake;
			env.relay_ok = islocalhost(&env, &fake.sin_addr);
		    }
		}
#endif
		break;
	case 'q':
		if ( env.bmode == 'p' )
		    /*add_pquery(z_optarg)*/;
		else if (z_optarg && *z_optarg) {
		    value(z_optarg, &qruntime, "m=1,h=60,d=1440");
		}
		else
		    env.bmode = 'q';
		break;
	case 't':
		env.trawl = 1;	/* scrounge the message header looking for
				 * recipients (pine sucks)
				 */
		break;
	case 'r':
	case 'f':
		env.forged = (env.sender != 0);
		from = z_optarg;
		break;
	case 'd':
		if (z_optarg)
		    sendmaild0 = (strcmp(z_optarg, "0") == 0)
			      || (strncmp(z_optarg, "0.", 2) == 0);
		else
		    debug = 1;
		break;
	case 'b':
		env.bmode = z_optarg[0];
		break;
	case 'o':
		set_option( 0, z_optarg, &env );
		break;
	case 'v':
		env.verbose = 1;
		break;
	case 'V':
		if (strcasecmp(pgm, "postoffice") == 0)
		    printf("%s %s\n", pgm, myversion);
		else
		    printf("%s: postoffice %s\n", pgm, myversion);
		exit(EX_OK);
	}
    }

    if (sendmaild0)
	printf("Version %s\n", myversion);

    if (strchr(modes, env.bmode)) {
	switch (env.bmode) {
	case 's':
		superpowers();
		if ( !Cflag ) configfile(1, CONFDIR "/postoffice.cf", &env);
		smtp(stdin, stdout, peer, &env);
		exit(EX_TEMPFAIL);
	case 'd':
	case 'D':
		if (getuid() == 0) {
		    if (env.bmode == 'd')
			daemonize(&env, debug);
		    if (qruntime) {
			pid_t qd;

			if ( (qd=fork()) == -1) {
			    syslog(LOG_ERR, "starting runqd: %m");
			    exit(EX_TEMPFAIL);
			}
			else if (qd == 0) {
			    runqd(&env,qruntime);
			    exit(EX_TEMPFAIL);
			}
		    }

		    if ( !Cflag ) configfile(1, CONFDIR "/postoffice.cf", &env);
		    if (env.auditing)
			auditon(0);
		    else
			auditoff(0);
		    server(&env, debug);
		    exit(EX_OK);
		}
		fprintf(stderr, "%s: Permission denied.\n", pgm);
		exit(EX_NOPERM);
	case 'p':
		superpowers();
		listq();
		break;
	case 'm':
		if (qruntime) {
		    if (getuid() == 0) {
			daemonize(&env, debug);
			runqd(&env, qruntime);
			exit(EX_OK);
		    }
		    fprintf(stderr, "%s: Permission denied.\n", pgm);
		    exit(EX_NOPERM);
		}
		else {
		    superpowers();
		    if ( !Cflag ) configfile(1, CONFDIR "/postoffice.cf", &env);
		    mail(from, argc-z_optind, argv+z_optind, &env);
		}
		break;
	case 'q':
		superpowers();
		if ( !Cflag ) configfile(1, CONFDIR "/postoffice.cf", &env);
		runq(&env);
		break;
	case 'i':	/* initialize alias database */
		superpowers();
		newaliases(argc-z_optind, argv+z_optind);
		break;
	}
	exit(EX_OK);
    }
    fprintf(stderr, "%s: mode <%c> is not implemented\n", pgm, env.bmode);
    exit(EX_USAGE);
}
