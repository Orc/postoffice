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
#include "spool.h"
#include "public.h"

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
	if ( setgid(to->gid) || setuid(to->uid) ) {
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
	execlp("/bin/sh", "sh", "-c", (to->fullname) + 1, (char*)0);
	syslog(LOG_ERR, "cannot exec %s: %m", to->fullname);
	fseek(let->log, 0L, SEEK_END);
	fprintf(let->log, "cannot exec %s\n", to->fullname);
	exit(EX_OSERR);
    }

    close(io[0]);

    mboxfrom(f, let);
    addheaders(f, let);
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


/* fork off a child process to actually put the message
 * into a mailbox.   Can't use setreuid/gid because that
 * doesn't work on FreeBSD 7.2 (!?!)
 */
static int
mbox(struct letter *let, struct recipient *to, char *mbox)
{
    int status = 0;
    FILE *f;
    pid_t writer = fork();

    if ( writer == 0 ) {
	/* child */
	umask(077);
	if ( setgid(to->gid) || setuid(to->uid) || !(f = fopen(mbox,"a")) ) {
	    syslog(LOG_ERR, "%s: %m", to->fullname);
	    fprintf(let->log, CannotWrite, to->user, strerror(errno));
	    exit(1);
	}
	locker(fileno(f), LOCK_EX);

	mboxfrom(f, let);
	addheaders(f, let);
	copybody(f, let);
	putc('\n', f);

	locker(fileno(f), LOCK_UN);
	fclose(f);
	exit(0);
    }
    else if ( writer > 0 && (waitpid(writer, &status, 0) != -1
					    || errno == ECHILD) )
	    return WEXITSTATUS(status) ? 0 : 1;

    syslog(LOG_ERR, "%s: %m", to->fullname);
    fprintf(let->log, CannotWrite, to->user, strerror(errno));
    let->fatal = 1;
    return 0;
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
oktowrite(struct recipient *to)
{
    if (to->gid == 0 || to->uid == 0) {
	syslog(LOG_ERR, "file [%s] you are root (%d %d)",
			to->fullname, to->uid, to->gid);
	return 0;
    }
    return 1;
}


static int
spam(struct letter *let, struct recipient *to, struct spam *what)
{
    struct passwd *pwd = getpwemail(to->dom, to->user);
    char *sf, *file, *junkfolder;
    int size;

    if (!oktowrite(to))
	return 0;

    if (what->action != spFILE)
	return 0;

    if ( pwd == 0 || (file = mailbox(to->dom,pwd->pw_name)) == 0 ) {
	fprintf(let->log, SuspiciousName, to->user);
	syslog(LOG_ERR, "<%s> is a bogus username", to->user);
	return 0;
    }

    if ( !(sf = what->folder) ) {
	syslog(LOG_ERR, "empty spam.folder.  This is a CANTHAPPEN error?");
	return 0;
    }

    if ( strncmp(sf, "~/", 2) == 0 ) {
	/* spamfolder is relative to user's homedir */

	if (pwd->pw_dir == 0)
	    return 0; /* no home directory == can't put spam in spamfolder */

	size = strlen(pwd->pw_dir) + 1 + strlen(sf+2) + 1;
	junkfolder = malloc(size);
	sprintf(junkfolder, "%s/%s", pwd->pw_dir, sf+2);
	return mbox(let, to, junkfolder);
    }
    /* otherwise it's a different mailbox in the maildir */

    if (junkfolder = alloca(strlen(file) + strlen(what->folder) + 2)) {
	sprintf(junkfolder, "%s:%s", file, what->folder);
	return mbox(let, to, junkfolder);
    }
    syslog(LOG_ERR, "out of memory in spam()");
    return 0;
}


static int
file(struct letter *let, struct recipient *to)
{
    if (oktowrite(to))
	return mbox(let,to,to->fullname);
    fprintf(let->log, blocked, to->user);
    return 0;
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
	case emBLACKLIST:
		    rc = spam(let, &(let->local.to[count]), & let->env->rej );
		    break;
	case emSPAM:rc = spam(let, &(let->local.to[count]), & let->env->spam );
		    break;
	case emUSER:rc = post(let, &(let->local.to[count]) );
		    break;
	case emFILE:rc = file(let, &(let->local.to[count]) );
		    break;
	default:    rc = 0;
		    break;
	}

	if (rc > 0) {
	    char *typ;

	    switch (let->local.to[count].typ) {
	    case emBLACKLIST:   typ = "[BLACKLIST]";
				break;
	    case emSPAM:	typ = "[SPAM]";
				break;
	    default:		typ = "";
				break;
	    }
	    syslog(LOG_INFO, "deliver mail from %s (%s) to %s (%s)%s",
		fromwho(let->from), let->deliveredby,
		username(let->local.to[count].dom, let->local.to[count].user),
		let->local.to[count].fullname, typ);
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
