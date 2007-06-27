#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>

#include "spool.h"
#include "bounce.h"

char pidf [sizeof(QRUNPFX) + 10];
char xtemp[sizeof(QRUNPFX) + 10];

static int
too_old(struct letter *let, char *dfile)
{
    struct stat finfo;

    if (stat(dfile, &finfo) != 0)
	return 0;

    return (difftime(time(0), finfo.st_mtime)  > let->env->qreturn);
}

static void
runremote(struct letter *let, char *qid)
{
    char dfile[sizeof(DATAPFX) + 10];
    char cfile[sizeof(CTRLPFX) + 10];
    extern char replytext[];
    int status = 0;
    int fd;

    sprintf(cfile, CTRLPFX "%.9s", qid);
    sprintf(dfile, DATAPFX "%.9s", qid);

    if (readcontrolfile(let, qid)) {
	if (let->remote.count > 0) {
	    if ( (fd = open(dfile, O_RDONLY)) != -1) {
		let->bodytext = mapfd(fd, &let->bodysize);
		close(fd);
	    }

	    if (let->bodytext == 0) {
		/* lost the message body; need to write back an
		 * error message reporting the horrible news
		 */
		bounce(let, "\tA horrible system error happened and\n"
			    "\tyour mail was eaten by the computer!\n",
			    -1, PENDING);

		unlink(dfile);
		unlink(cfile);
		return;
	    }
	    replytext[0] = 0;
	    forward(let);
	}
	if ( too_old(let, dfile) ) {
	    char why[100];
	    unsigned int d, h, m;
	    unsigned int t = let->env->qreturn;

	    sprintf(why, "\tCould not deliver mail for");

	    if (d = t/(24*3600))
		sprintf(why+strlen(why), " %d day%s", d, (d!=1)?"s":"");

	    t %= (24*3600);
	    if (h = t/3600)
		sprintf(why+strlen(why), "%s %d hour%s",
			    d?",":"", h, (h!=1)?"s":"");

	    t %= 3600;
	    if (m = t / 60)
		sprintf(why+strlen(why), "%s %d minute%s",
			    (d || h)?" and":"", m, (m!=1)?"s":"");

	    bounce(let, why, -1, PENDING);
	    unlink(cfile);
	    unlink(dfile);
	}
	else if (pending(let->remote)) {
	    let->qcomment = replytext;
	    writecontrolfile(let);
	}
	else {
	    unlink(cfile);
	    unlink(dfile);
	}
    }
    else if (let->env->verbose && (errno != ENOENT))
	fprintf(stderr, "could not read control file %s: %s\n",
			qid, strerror(errno));
}


runjob(struct letter *let, char *qid)
{
#ifdef NO_FLOCK
    pid_t qpid;
    int runit;
    FILE *f;

    strcpy(xtemp, QRUNPFX);
    strcat(xtemp, qid);

    while ( !(runit = (link(pidf, xtemp) != -1)) && (errno == EEXIST)) {
	/* if I can't take the xfile, see if the
	 * xfile is owned by someone who still
	 * exists.
	 */
	qpid = -1;
	if (f = fopen(xtemp, "r")) {
	    fscanf(f, "%d", &qpid);
	    fclose(f);
	}
	if ( (qpid != -1) && (kill(qpid, 0) == 0) )
	    break;

	syslog(LOG_INFO, (qpid == -1) ? "Zombie QID %s"
				      : "Zombie QID %s (pid %d)",
			  qid, qpid);
	unlink(xtemp);
    }

    if (runit) {
	runremote(let, qid);
	unlink(xtemp);
    }
    else if ( let->env->verbose && (errno != EEXIST) )
	perror(qid);
#else
    int fd;

    strcpy(xtemp, QRUNPFX);
    strcat(xtemp, qid);

    if ( (fd = open(xtemp, O_RDWR)) == -1) {
	if (errno != ENOENT)
	    perror(qid);
    }
    else {
	if ( flock(fd, LOCK_EX|LOCK_NB) == 0 ) {
	    runremote(let, qid);
	    flock(fd, LOCK_UN);
	}
	else if (errno != EWOULDBLOCK)
	    perror(qid);
	close(fd);
    }
#endif
}

int
runlock()
{
#ifdef NO_FLOCK
    int fd;

    sprintf(pidf, QUEUEDIR "qXXXXXX");
    if ( (fd = mkstemp(pidf)) == -1) {
	syslog(LOG_ERR, "%s: %m", pidf);
	return 0;
    }
    else {
	char pidline[40];
	sprintf(pidline, "%d\n", getpid());
	write(fd, pidline, strlen(pidline));
	close(fd);
    }
    return 1;
#endif
}


void
rununlock()
{
#ifdef NO_FLOCK
    unlink(pidf);
#endif
}


int
runq(struct env *env)
{
    DIR *d;
    struct dirent *de;
    struct letter let;
    time_t t = time(0);
    char timeofday[80];

    strftime(timeofday, sizeof timeofday, "%I:%M %p  %b %d, %Y", localtime(&t));

    setproctitle("runq @ %s", timeofday);

    if ( !runlock() ) return 0;

    if ( (d = opendir(QUEUEDIR)) == 0 ) {
	syslog(LOG_ERR, "%s: %m", QUEUEDIR);
	return 0;
    }

    prepare(&let, stdin, stdout, env);

    while (de = readdir(d))
	if (Qpicker(de))
	    runjob(&let, de->d_name + 2);
    
    closedir(d);
    close_sessions();

    rununlock();
    return 1;
}
