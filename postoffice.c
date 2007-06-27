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

#include "letter.h"
#include "smtp.h"

void
superpowers()
{
    if (getuid() != geteuid()) {
	/* pick up our superpowers powers (if any) */
	setuid(geteuid());
	setgid(getegid());
    }
}

float
main(int argc, char **argv)
{
    int opt;
    int val;
    int auditing = 0;
    extern struct in_addr *local_if_list();
    struct sockaddr_in *peer = 0;	/* peer for -bs (for debugging) */
    static ENV env;
    char *pgm;
    char *from = 0;
    char *options = "aA:B:C:F:f:r:b:o:h:R:GUimnqv";
    char *modes = "sqpmid";
    struct utsname sys;
    struct hostent *p;

    env.bmode = 'm';
    env.local_if = local_if_list();
    env.relay_ok = 1;		/* allow local relaying */
    env.verbose = 0;		/* be chattery */
    env.nodaemon = 0;		/* allow MAIL FROM:<> */
    env.delay = 3600;		/* greylist delay */
    env.largest = 0;
    env.sender = getuid();
    env.timeout = 300;
    env.qreturn = 86400*3;
    env.max_loadavg = 4.0;
    env.max_clients = 100;	/* should be fairly ridiculous */
    env.max_hops = 100;		/* (ditto) */
    env.argv0 = argv[0];

    if ( p = gethostbyname((uname(&sys) == 0) ? sys.nodename : "localhost") )
	env.localhost = strdup(p->h_name);
    else
	env.localhost = "localhost";

    pgm = strdup(basename(argv[0]));
    openlog(pgm, LOG_PID, LOG_MAIL);

#define SAME(a,b)	(strcasecmp(a,b) == 0)

    /* handle magic program names */
    if ( SAME(pgm, "mailq") ) {
	options = "v";
	env.bmode = 'p';
    }
    else if ( SAME(pgm, "sendmail") || SAME(pgm, "send-mail") ) {
	options = "b:F:f:io:r:vt";
	modes = "sm";
	env.bmode = 'm';
    }
    else if ( SAME(pgm, "runq") ) {
	options = "v";
	env.bmode = 'q';
    }
    else if ( SAME(pgm, "newaliases") ) {
	options = "v";
	env.bmode = 'i';
    }
    else if ( SAME(pgm, "smtpd") ) {
	options = "aA:B:C:o:h:R:GUmnv";
	env.bmode = 'd';
    }

    while ( (opt = getopt(argc, argv, options)) != EOF) {
	switch (opt) {
	case 'a':
		auditing = 1;
		break;
	case 'C':
		if (configfile(optarg, &env) == 0) {
		    perror(optarg);
		    exit(EX_NOINPUT);
		}
		break;
#ifdef USE_PEER_FLAG
	case 'R':
		{   struct sockaddr_in fake;
		    union {
			long num;
			struct in_addr a;
		    } ip;

		    if ( (ip.num = inet_addr(optarg)) != -1) {
			fake.sin_addr = ip.a;
			fake.sin_family = AF_INET;
			peer = &fake;
		    }
		}
		break;
#endif
	case 'q':
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
		from = optarg;
		break;
	case 'b':
		env.bmode = optarg[0];
		break;
	case 'o':
		set_option(optarg, &env);
		break;
	case 'v':
		env.verbose = 1;
		break;
	}
    }

    if (strchr(modes, env.bmode)) {
	switch (env.bmode) {
	case 's':
		superpowers();
		smtp(stdin, stdout, peer, &env);
		exit(EX_TEMPFAIL);
	case 'd':
		if (getuid() == 0) {
		    if (auditing)
			auditon();
		    else
			auditoff();
		    server(&env);
		    break;
		}
		fprintf(stderr, "%s: Permission denied.\n", pgm);
		exit(EX_NOPERM);
	case 'p':
		superpowers();
		listq();
		break;
	case 'm':
		superpowers();
		mail(from, argc-optind, argv+optind, &env);
		break;
	case 'q':
		superpowers();
		runq(&env);
		break;
	case 'i':	/* initialize alias database */
		superpowers();
		newaliases();
		break;
	}
	exit(EX_OK);
    }
    fprintf(stderr, "%s: mode <%c> is not implemented\n", pgm, env.bmode);
    exit(EX_USAGE);
}
