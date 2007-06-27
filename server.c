/*
 * smtp gateway server
 */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <syslog.h>
#include <ctype.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h>
#include <signal.h>
#include <sysexits.h>

#include <stdarg.h>
#include <time.h>
#include <syslog.h>

#include "letter.h"
#include "smtp.h"
#include "mx.h"



/*
 * is this IP address one of our local ones?
 */
int
islocalhost(ENV *env, struct in_addr *host)
{
    struct in_addr *p;

    for ( p = env->local_if; p->s_addr; p++ )
	if (host->s_addr == p->s_addr)
	    return 1;

    return 0;
}


/*
 * nameof() an IP connection
 */
char*
nameof(struct sockaddr_in *peer)
{
    char *host;

    host = ptr(&peer->sin_addr);

    return host ? host : inet_ntoa(peer->sin_addr);
}


static struct window {
    pid_t clerk;
    struct sockaddr_in customer;
} *window = 0;

static int nwindow = 0;

static int
isconnected(int i)
{
    int j;
    struct window *p, *n;

#define Cus_addr customer.sin_addr.s_addr

    n = window+i;
    for (p=window+0, j=nwindow; j-- > 0; p++)
	if (p->clerk != -1 && (p->Cus_addr == n->Cus_addr) )
	    return 1;
    return 0;

#undef Cus_addr
}


void
reaper(int sig)
{
    int i, status;
    pid_t z;

    while ( (z = wait3(&status, WNOHANG, 0)) > 0) {
	for (i = nwindow; i-- > 0; )
	    if (z == window[i].clerk)
		window[i].clerk = -1;
    }
    signal(sig, reaper);
}


static void
sigexit(int sig)
{
    syslog(LOG_ERR, "server exit on signal %d", sig);
    exit(EX_TEMPFAIL);
}


static int
attach(int port)
{
    struct sockaddr_in service = { AF_INET };
    int size;
    int ret;
    int on = 1;

    service.sin_port = port;

    if ( (ret = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	return -1;

    setsockopt(ret, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    setsockopt(ret, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof on);

    if (bind(ret, (struct sockaddr *)&service, sizeof service) < 0)
	return -1;

    if (listen(ret, 5) == -1) {
	close(ret);
	return -1;
    }
    return ret;
}


static int
do_smtp_connection(int client, ENV *env)
{
    FILE *in = 0,
	 *out = 0;
    double loadavg[3];
    pid_t child;
    time_t now;
    char *peername;
    int ret = 0, i, cs;

    for (i=nwindow; i-- > 0; )
	if (window[i].clerk == -1)
	    break;

    cs = sizeof window[i].customer;


    if ( ! ((in = fdopen(client, "r")) && (out=fdopen(client,"w"))) ) {
	syslog(LOG_ERR, "fdopen: %m" );
	write(client, "451 SYSTEM ERROR.  "
			  "PLEASE TRY AGAIN LATER.\r\n", 44);
    }
    else if (i < 0 || getloadavg(loadavg, 3) < 1
		   || loadavg[0] > env->max_loadavg) {
	message(out, 451, "I'm too busy. Please try again later.");
    }
    else if (getpeername(client, &window[i].customer, &cs) == -1) {
	message(out, 451, "System error.  Please try again later.");
	ret = -1;
    }
    else if (isconnected(i) && !islocalhost(env,&window[i].customer.sin_addr)) {
	message(out, 451, "You are already connected to "
			  "this mail server. Finish that session "
			  "and try again.");
    }
    else if ( (child = window[i].clerk = fork()) == -1 ) {
	syslog(LOG_ERR, "%s - fork: %m", nameof(&window[i].customer) );
	message(out, 451, "System error.  Please try again later.");
    }
    else if (child == 0) {

	signal(SIGCHLD, SIG_DFL);
	signal(SIGUSR2, SIG_IGN);
	signal(SIGUSR1, SIG_IGN);
	setsid();

	memset(env->argv0, 0, 80);
	strcpy(env->argv0, "SMTP startup");
	peername = nameof(&window[i].customer);
	sprintf(env->argv0, "SMTP %s       ", peername);
	alarm(300);	/* give the client 5 minutes to set up a connection */

	env->relay_ok = islocalhost(env, &window[i].customer.sin_addr);

	if ( env->localmx && !env->relay_ok ) {
	    /* Dangerous option:  if we're an MX for a client,
	     * they can relay through us.   The danger here is
	     * that we have to trust the DNS system, and if a
	     * scammer makes us their MX we'll become a zombie
	     * spam client.
	     */
	    struct iplist mx;
	    int i;

	    getMXes(peername, &mx);

	    for ( i = mx.count; i-- > 0; )
		if (islocalhost(env, &mx.a[i].addr)) {
		    syslog(LOG_INFO, "%s is a local mx", peername);
		    env->relay_ok = 1;
		    break;
		}
	    freeiplist(&mx);
	}
	smtp(in, out, &window[i].customer, env);
	exit(EX_OK);
    }
    if (in) fclose(in);
    if (out) fclose(out);

    return ret;
}


static void
crash(int sig)
{
    syslog(LOG_ERR, "CRASH with signal %d", sig);
    abort();
}


void
server(ENV *env, int debug)
{
    struct servent *proto = getservbyname("smtp", "tcp");
    int port = proto ? proto->s_port : htons(25);
    unsigned int errcount;
    int sock, client;
    int status, nul, i;
    pid_t daemon;

    nwindow = env->max_clients;
    if ( (window = calloc(sizeof window[0], nwindow)) == 0 ) {
	syslog(LOG_ERR, "alloc %d windows: %m", nwindow);
	exit(EX_OSERR);
    }
    for (i=nwindow; i-- > 0; )
	window[i].clerk = -1;

    if (debug) {
	printf("debug server: startup\n");
    }
    else {
	close(0);
	close(1);
	close(2);
	setsid();

	if ( (daemon = fork()) == -1) {
	    syslog(LOG_ERR, "starting mail server: %m");
	    exit(EX_OSERR);
	}
	else if (daemon > 0)
	    exit(EX_OSERR);

	if ( (nul = open("/dev/null", O_RDWR)) != -1
				&& dup2(nul,0) != -1
				&& dup2(nul,1) != -1
				&& dup2(nul,2) != -1)
	    close(nul);
	else {
	    syslog(LOG_ERR, "Cannot attach to /dev/null: %m");
	    exit(EX_OSERR);
	}
    }


    for (i=1; i < NSIG; i++) {
	void (*sig)(int);

	if (i == SIGABRT)
	    continue;
	else if ( (sig = signal(i, crash)) != SIG_DFL) {
	    signal(i, sig);
	    syslog(LOG_INFO, "signal %d was set by postoffice", i);
	}
    }

    signal(SIGHUP,  sigexit);
    signal(SIGINT,  sigexit);
    signal(SIGQUIT, sigexit);
    signal(SIGKILL, sigexit);
    signal(SIGTERM, sigexit);
    signal(SIGUSR2, sigexit);
    signal(SIGCHLD, reaper);
    signal(SIGPIPE, SIG_IGN);

reattach:
    if ( (sock = attach(port)) == -1) {
	syslog(LOG_ERR, "daemon cannot attach: %m");
	exit(EX_OSERR);
    }

    while (1) {
	struct sockaddr j;
	int js = sizeof j;

	if ( (client = accept(sock, &j, &js)) == -1 ) {
	    if (errno == EINTR)
		continue;
	    else if (errno == EBADF) {
		syslog(LOG_ERR, "accept: %m -- restarting daemon");
		close(sock);
		sleep(60);
		goto reattach;
	    }
	    else {
		syslog(LOG_ERR, "accept: %m");
		if (debug) printf("debug server:%s\n", strerror(errno));
		errcount++;
	    }
	}
	else {
	    if (debug) printf("debug server:session\n");
	    status = do_smtp_connection(client, env);
	    close(client);
	    if (status < 0) {
		syslog(LOG_ERR, "%m -- restarting daemon");
		close(sock);
		sleep(60);
		goto reattach;
	    }
	}
    }
    syslog(LOG_ERR, "daemon aborting: %m");
}
