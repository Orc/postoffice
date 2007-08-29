/*
 * local mail processing
 */

#include "config.h"

#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <paths.h>
#include <errno.h>
#include <sysexits.h>
#include <string.h>

#include "letter.h"

static char blocked[] = "Mail to %s is blocked by security policy\n";
static char CannotWrite[] = "Cannot write to mailbox for %s: %s\n";
static char SuspiciousName[] = "<%s> is not a username I like\n";

#ifndef HAVE_MEMSTR
static char *
memstr(char *haystack, char *needle, int size)
{
    char *p;
    int szneedle;
    char *end;

    if ( !(/*haystack && needle &&*/size) )
	return 0;

    szneedle = strlen(needle);
    end = haystack + size - szneedle;

    for (p = haystack; p < end;  ) {
	if ( (p = memchr(p, needle[0], end-p)) == 0 )
	    return 0;
	if (memcmp(p, needle, szneedle) == 0)
	    return p;
	++p;
    }
    return 0;
}
#endif


static void
copybody(FILE *f, struct letter *let)
{

#define DO_OR_DIE(x,ret)	if ( x != ret) return

    if (!let->has_headers)
	DO_OR_DIE(fputc('\n', f), '\n');

    if (let->env->escape_from) {
	char *p, *n;
	char *end = let->bodytext + let->bodysize;

	for (p = let->bodytext; p ; p = n) {
	    if ( n = memstr(p+1, "\nFrom ", end - (p+1)) ) {
		n++;	/* skip past leading \n */
		DO_OR_DIE(fwrite(p, (n-p), 1, f), 1);
		DO_OR_DIE(fputc('>', f), '>');
	    }
	    else
		DO_OR_DIE(fwrite(p, (end-p), 1, f), 1);
	}
    }
    else
	DO_OR_DIE(fwrite(let->bodytext, let->bodysize, 1, f), 1);
    fflush(f);
}


static int
_exe(struct letter *let, struct recipient *to)
{
    int io[2];
    FILE *f;
    pid_t child;
    int rc;
    struct passwd *pwd;

    if (to->uid == 0 || to->gid == 0) {
	fprintf(let->log, blocked, to->user);
	syslog(LOG_ERR, "exe [%s] you are root (%d %d)", to->fullname, to->uid, to->gid);
	return 0;
    }


    if (pipe(io) != 0) {
	fprintf(let->log, CannotWrite, to->user, strerror(errno));
	syslog(LOG_ERR, "exe [%s]: %m", to->fullname);
	return 0;
    }

    fflush(let->log);
    if ( (f = fdopen(io[1], "w")) == 0 || (child = fork()) == -1) {
	fprintf(let->log, CannotWrite, to->user, strerror(errno));
	syslog(LOG_ERR, "exe [%s]: %m", to->fullname);
	if (f) fclose(f);
	close(io[0]);
	close(io[1]);
	return 0;
    }
    if (child == 0) {
	/* I am the child */
	if ( setregid(to->gid, to->gid) || setreuid(to->uid, to->uid) ) {
	    fprintf(let->log, CannotWrite, to->user, strerror(errno));
	    syslog(LOG_ERR, "cannot drop privileges: %m\n");
	    exit(EX_OSERR);
	}

	close(io[1]);
	dup2(io[0], 0);
	dup2(fileno(let->log), 1);
	dup2(fileno(let->log), 2);

	if ( (pwd = getpwuid(to->uid)) == 0 || chdir(pwd->pw_dir) == -1)
	    chdir("/tmp");

	nice(5);
	execlp("/bin/sh", "sh", "-c", (to->fullname) + 1, 0);
	syslog(LOG_ERR, "cannot exec %s: %m", to->fullname);
	fseek(let->log, 0L, SEEK_END);
	fprintf(let->log, "cannot exec %s\n", to->fullname);
	exit(EX_OSERR);
    }

    close(io[0]);

    mboxfrom(f, let);
    addheaders(f, let, to);
    copybody(f, let);
    rc = ferror(f);
    fclose(f);

    close(io[1]);

    if (waitpid(child, &let->status, 0) == -1 && errno != ECHILD) {
	syslog(LOG_ERR, "unexpected failure on [%s]: %m", to->fullname);
	return 0;
    }
    return (rc || WIFSIGNALED(let->status)) ? 0 : 1;
}


int
exe(struct letter *let, struct recipient *to)
{
    pid_t child = fork();

    if (child == -1) {
	fprintf(let->log, CannotWrite, to->user, strerror(errno));
	syslog(LOG_ERR, "exe [%s]: %m", to->fullname);
	return 0;
    }
    else if (child == 0) {
	if (_exe(let, to) != 0)
	    exit(WEXITSTATUS(let->status));
	exit(EX_OK);
    }

    if (waitpid(child, &let->status, 0) == -1 && errno != ECHILD) {
	syslog(LOG_ERR, "unexpected failure on [%s]: %m", to->fullname);
	return 0;
    }
    return WEXITSTATUS(let->status) ? 0 : 1;
}


static int
mbox(struct letter *let, struct recipient *to, char *mbox)
{
    int status = 0;
    FILE *f;
    uid_t saveuid = getuid();

    if ( setregid(-1, to->gid) || setreuid(-1, to->uid) ) {
	syslog(LOG_ERR, "cannot drop privileges: %m\n");
	fprintf(let->log, CannotWrite, to->user, strerror(errno));
	return 0;
    }
    umask(077);
    if ( (f = fopen(mbox, "a")) == 0) {
	syslog(LOG_ERR, "%s: %m", to->fullname);
	fprintf(let->log, CannotWrite, to->user, strerror(errno));
    }
    else {
	flock(fileno(f), LOCK_EX);

	mboxfrom(f, let);
	addheaders(f, let, to);
	copybody(f, let);
	putc('\n', f);

	flock(fileno(f), LOCK_UN);
	fclose(f);
	status = 1;
    }

    if (setreuid(-1, saveuid) || setregid(-1, saveuid) ) {
	syslog(LOG_ERR, "cannot regain privileges: %m\n");
	fprintf(let->log, "Fatal error writing to mailbox for %s: %s\n",
			to->user, strerror(errno));
	let->fatal = 1;
	return 0;
    }
    return status;
}


static int
post(struct letter *let, struct recipient *to)
{
    struct passwd *pwd = getpwemail(to->dom, to->user);
    char *file;

    if ( pwd == 0 || (file = mailbox(to->dom,pwd->pw_name)) == 0 ) {
	fprintf(let->log, SuspiciousName, to->user);
	syslog(LOG_ERR, "<%s> is a bogus username", to->user);
	return 0;
    }
    return mbox(let, to, file);
}


static int
file(struct letter *let, struct recipient *to)
{
    if (to->gid == 0 || to->uid == 0) {
	fprintf(let->log, blocked, to->user);
	syslog(LOG_ERR, "file [%s] you are root (%d %d)",
			to->fullname, to->uid, to->gid);
	return 0;
    }
    return mbox(let, to, to->fullname);
}


static char
*fromwho(struct address *from)
{
    if (from->full && from->full[0])
	return from->full;
    return "<>";
}

int
runlocal(struct letter *let)
{
    int count;
    int rc;
    int completed = 0;

    umask(077);
    if ( ! (let->log || (let->log = tmpfile())) ) {
	syslog(LOG_ERR, "Cannot create transaction log: %m");
	let->log = stderr;
    }

    for (count=let->local.count; (count-- > 0) && !let->fatal; ) {
	if (let->local.to[count].status != PENDING)
	    continue;
	switch (let->local.to[count].typ) {
	case emEXE: rc = exe(let, &(let->local.to[count]) );
		    break;
	case emUSER:rc = post(let, &(let->local.to[count]) );
		    break;
	case emFILE:rc = file(let, &(let->local.to[count]) );
		    break;
	default:    rc = 0;
		    break;
	}

	if (rc > 0) {
	    syslog(LOG_INFO, "deliver mail from %s (%s) to %s (%s)",
		fromwho(let->from), let->deliveredby,
		username(let->local.to[count].dom, let->local.to[count].user),
		let->local.to[count].fullname );
	    completed += rc;
	}
	else 
	    syslog(LOG_ERR, "delivery failed from %s (%s) to %s (%s)",
		fromwho(let->from), let->deliveredby,
		username(let->local.to[count].dom, let->local.to[count].user),
		let->local.to[count].fullname);


    }
    return completed;
}
