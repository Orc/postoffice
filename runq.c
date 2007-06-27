#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "spool.h"
#include "bounce.h"

char pidf [sizeof(QRUNPFX) + 10];
char xtemp[sizeof(QRUNPFX) + 10];

static int
finished(struct letter *let)
{
    int i;
    int active = 0;

    for (i=0; i < let->remote.count; i++)
	if (let->remote.to[i].status == PENDING)
	    ++active;

    return (active == 0);
}


static void
runjob(struct letter *let, char *qid)
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
	if (finished(let)) {
	    unlink(cfile);
	    unlink(dfile);
	}
	else {
	    let->qcomment = replytext;
	    writecontrolfile(let);
	}
    }
    else if (let->env->verbose)
	fprintf(stderr, "could not read control file %s: %s\n",
			qid, strerror(errno));
}


int
runq(struct env *env)
{
    DIR *d;
    struct dirent *de;
    FILE *f;
    pid_t qpid;
    int runit;
    int fd;
    char pidline[40];
    struct letter let;

    sprintf(pidf, SPOOLDIR "qXXXXXX");
    if ( (fd = mkstemp(pidf)) == -1) {
	syslog(LOG_ERR, "%s: %m", pidf);
	return 0;
    }
    sprintf(pidline, "%d\n", getpid());
    write(fd, pidline, strlen(pidline));
    close(fd);

    if ( (d = opendir(SPOOLDIR)) == 0 ) {
	syslog(LOG_ERR, "%s: %m", SPOOLDIR);
	return 0;
    }

    prepare(&let, stdin, stdout, env);

    while (de = readdir(d)) {
	if (Qpicker(de)) {
	    strcpy(xtemp, QRUNPFX);
	    strcat(xtemp, de->d_name + 2);

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
		if (qpid != -1 && kill(qpid, 0) == 0)
		    break;

		syslog(LOG_INFO, (qpid == -1) ? "Zombie QID %s"
					      : "Zombie QID %s (pid %d)",
				  de->d_name+2, qpid);
		unlink(xtemp);
	    }

	    if (runit) {
		runjob(&let, de->d_name + 2);
		unlink(xtemp);
	    }
	    else if ( env->verbose && (errno != EEXIST) )
		perror(de->d_name + 2);
	}
    }
    
    closedir(d);
    unlink(pidf);
    close_sessions();

    return 1;
}
