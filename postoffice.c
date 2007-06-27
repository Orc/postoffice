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

char *pgm;

float
main(int argc, char **argv)
{
    int opt;
    extern struct in_addr *local_if_list();
    struct sockaddr_in *peer = 0;	/* peer for -bs (for debugging) */
    static ENV env;
    char *from = 0;
    char *options = "aA:B:C:dF:f:r:b:o:h:R:GUVimnqv";
    char *modes = "sqpmid";
    struct utsname sys;
    struct hostent *p;
    int debug = 0;

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

    env.argv0 = argv[0];

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
	options = "vV";
	env.bmode = 'p';
    }
    else if ( SAME(pgm, "sendmail") || SAME(pgm, "send-mail") ) {
	options = "A:b:F:f:imo:r:Vvt";
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
	options = "aA:B:C:do:h:R:GUmnvV";
	env.bmode = 'd';
    }

    while ( (opt = getopt(argc, argv, options)) != EOF) {
	switch (opt) {
	case 'a':
		env.auditing = 1;
		break;
	case 'C':
		if (configfile( optarg, &env ) == 0) {
		    perror(optarg);
		    exit(EX_NOINPUT);
		}
		break;
	case 'R':
#ifdef USE_PEER_FLAG
		{   struct sockaddr_in fake;
		    long ip;

		    if ( (ip = inet_addr(optarg)) != -1) {
			fake.sin_addr = inet_makeaddr(ntohl(ip), 0L);
			fake.sin_family = AF_INET;
			peer = &fake;
			env.relay_ok = islocalhost(&env, &fake.sin_addr);
		    }
		}
#endif
		break;
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
	case 'd':
		debug = 1;
		break;
	case 'b':
		env.bmode = optarg[0];
		break;
	case 'o':
		set_option( optarg, &env );
		break;
	case 'v':
		env.verbose = 1;
		break;
	case 'V':
		if (strcasecmp(pgm, "postoffice") == 0)
		    printf("%s %s\n", pgm, VERSION);
		else
		    printf("%s: postoffice %s\n", pgm, VERSION);
		exit(EX_OK);
	}
    }

    if (strchr(modes, env.bmode)) {
	switch (env.bmode) {
	case 's':
		superpowers();
		configfile("/etc/postoffice.cf", &env);
		smtp(stdin, stdout, peer, &env);
		exit(EX_TEMPFAIL);
	case 'd':
		if (getuid() == 0) {
		    configfile("/etc/postoffice.cf", &env);
		    if (env.auditing)
			auditon();
		    else
			auditoff();
		    server(&env,debug);
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
		configfile("/etc/postoffice.cf", &env);
		mail(from, argc-optind, argv+optind, &env);
		break;
	case 'q':
		superpowers();
		configfile("/etc/postoffice.cf", &env);
		runq(&env);
		break;
	case 'i':	/* initialize alias database */
		superpowers();
		newaliases(argc-optind, argv+optind);
		break;
	}
	exit(EX_OK);
    }
    fprintf(stderr, "%s: mode <%c> is not implemented\n", pgm, env.bmode);
    exit(EX_USAGE);
}
