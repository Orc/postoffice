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
 * write a message to the client, linewrapping at 70 columns.
 */
void
message(FILE *f, int code, char *fmt, ...)
{
    va_list ptr;
    static char bfr[10240];
    int size;
    int i, j, k;
    int dash = (code < 0);

    va_start(ptr, fmt);
    size = vsnprintf(bfr, sizeof bfr, fmt, ptr);
    va_end(ptr);

    if (dash) code = -code;

    for (i=0; i < size; i = j+1) {
	for (j=i; j < i+70 && j < size && bfr[j] != '\n'; j++)
	    ;
	if ( (j >= i + 70) && !isspace(bfr[j]) ) {
	    do {
		--j;
	    } while ( (j > i) && !isspace(bfr[j]) );

	    if (j == i)
		j = i + 70;
	}

	fprintf(f, "%03d%c", code, (dash || (j<size-1)) ? '-' : ' ');
	for ( ;i < j; i++)
	    fputc(toupper(bfr[i]), f);
	fputs("\r\n", f);
	fflush(f);
    }
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


static void
do_smtp_connection(int client, ENV *env)
{
    int i;
    int cs;
    FILE *in, *out;
    double loadavg[3];
    pid_t child;
    time_t now;
    char *peername;

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
	syslog(LOG_ERR, "getpeername: %m");
	message(out, 451, "System error.  Please try again later.");
    }
    else if (isconnected(i)) {
	message(out, 451, "You are already connected to "
			  "this mail server. Finish that session "
			  "and try again.");
    }
    else if ( (child = window[i].clerk = fork()) == -1 ) {
	syslog(LOG_ERR, "%s - fork: %m", nameof(&window[i].customer) );
	message(out, 451, "System error.  Please try again later.");
    }
    else if (child == 0) {
	struct in_addr *p;

	signal(SIGCHLD, SIG_DFL);
	signal(SIGUSR2, SIG_IGN);
	setsid();

	memset(env->argv0, 0, 80);
	strcpy(env->argv0, "SMTP startup");
	peername = nameof(&window[i].customer);
	sprintf(env->argv0, "SMTP %s       ", peername);
	alarm(300);	/* give the client 5 minutes to set up a connection */

	env->relay_ok = 0;

	for ( p = env->local_if; p->s_addr; p++ ) {
	    if (window[i].customer.sin_addr.s_addr == p->s_addr) {
		env->relay_ok = 1;
		break;
	    }
	}
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
		for ( p = env->local_if; p->s_addr; p++ )
		    if ( p->s_addr == mx.a[i].addr.s_addr ) {
			syslog(LOG_INFO, "%s is a local mx", peername);
			env->relay_ok = 1;
			goto fin;
		    }
	fin:freeiplist(&mx);
	}
	smtp(in, out, &window[i].customer, env);
	exit(EX_OK);
    }
    if (in) fclose(in);
    if (out) fclose(out);
}


void
server(ENV *env)
{
    struct servent *proto = getservbyname("smtp", "tcp");
    int port = proto ? proto->s_port : htons(25);
    unsigned int errcount;
    int sock, client;
    int nul, i;
    pid_t daemon;

    nwindow = env->max_clients;
    if ( (window = calloc(sizeof window[0], nwindow)) == 0 ) {
	syslog(LOG_ERR, "alloc %d windows: %m", nwindow);
	exit(EX_OSERR);
    }
    for (i=nwindow; i-- > 0; )
	window[i].clerk = -1;

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


    signal(SIGHUP,  sigexit);
    signal(SIGINT,  sigexit);
    signal(SIGQUIT, sigexit);
    signal(SIGKILL, sigexit);
    signal(SIGTERM, sigexit);
    signal(SIGUSR1, SIG_IGN);
    signal(SIGUSR2, sigexit);
    signal(SIGCHLD, reaper);

    for ( ; (sock = attach(port)) != -1; close(sock), sleep(30)) {

	errcount = 0;
	while (1) {
	    struct sockaddr j;
	    int js = sizeof j;

	    if ( (client = accept(sock, &j, &js)) < 0) {
		if (errno == EINTR)
		    continue;
		if (errno == EBADF) {
		    syslog(LOG_ERR, "%m -- restarting daemon");
		    break;
		}
		syslog(LOG_ERR, "accept: %m");
		if (++errcount > 100) {
		    syslog(LOG_ERR, "Too many errors on socket -- restarting");
		    break;
		}
		continue;
	    }
	    if (errcount)
		--errcount;

	    do_smtp_connection(client, env);
	    close(client);
	}
    }
    syslog(LOG_ERR, "daemon aborting: %m");
}
