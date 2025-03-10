#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <time.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#if HAVE_MALLOC_H
#   include <malloc.h>
#endif

#if HAVE_SYS_MOUNT_H
#   include <sys/param.h>
#   include <sys/mount.h>
#endif
#if HAVE_SYS_VFS_H
#   include <sys/vfs.h>
#endif
#if HAVE_SYS_STATVFS_H
#   include <sys/statvfs.h>
#endif

#include "spool.h"

#include "letter.h"
#include "env.h"
#include "mx.h"
#include "mymalloc.h"


int
mkspool(struct letter *let)
{
    static char tempfile[sizeof(TEMPPFX)+20+1];
    int f;

#if HAVE_STRUCT_STATFS || HAVE_STRUCT_STATVFS
#if HAVE_STATFS
#   define STATFS statfs
#   define F_BSIZE f_bsize
#else
#   define STATFS statvfs
#   define F_BSIZE f_frsize
#endif

    struct STATFS df;
    unsigned long size;

    if ( let->env && (let->env->minfree > 0) ) {
	if (STATFS(QUEUEDIR, &df) != 0) {
	    syslog(LOG_ERR, "stat(v)fs(%s): %m", QUEUEDIR);
	    return 0;
	}

	size = let->env->minfree / df.F_BSIZE;

	if (df.f_bavail < size) { 
	    syslog(LOG_ERR, "Disk too full (need %ld blocks, have %ld free)",
			    (long)let->env->minfree, (long)df.f_bavail);
	    return 0;
	}
    }
#endif

    strcpy(tempfile, TEMPPFX "XXXXXX");

    umask(077);
    if ( (f = mkstemp(tempfile)) == -1 || (let->body = fdopen(f, "w+")) == 0) {
	if (f != -1) close(f);
	syslog(LOG_ERR, "%s: %m", tempfile);
	return 0;
    }
    let->tempfile = tempfile;
    return 1;
}


int
notnull(struct address *from)
{
    return from && from->full && (from->full[0] != 0);
}


void
mboxfrom(FILE *f, struct letter *let)
{
    char date[80];

    if (let->mboxfrom) return;

    strftime(date, 80, "%a %b %d %H:%M:%S %Y", localtime(&let->posted));
    fprintf(f, "From %s %s\n", notnull(let->from) ? let->from->full
                                                  : "<>", date);
}


#if 0
static int
domaincmp(struct recipient *a, struct recipient *b)
{
    return strcmp(a->host, b->host);
}
#endif


static char*
restofline(char *p, char *q)
{
    char *ret;
    int size = q-p;

    if (size <= 0) {
	syslog(LOG_ERR, "restofline alloc %d bytes", size);
	abort();
    }

    if ( ret = malloc(size+1) ) {
	memcpy(ret, p, size);
	ret[size] = 0;
	return ret;
    }
    syslog(LOG_ERR,"restofline alloc %d byte%s: %m",size,(size==1)?"s":"");
    abort();

} /* restofline */


int
readcontrolfile(struct letter *let, char *qid)
{
    int   fd;
    char  ctrlfile[sizeof(CTRLPFX)+6+1];
    char *ctrl = 0;
    size_t size;
    char *sep;
    char *p, *q, *end;
    struct address to;

    sprintf(ctrlfile, CTRLPFX "%.6s", qid);

    if ( (fd = open(ctrlfile, O_RDONLY)) != -1) {
	ctrl = mapfd(fd, &size);
	close(fd);
    }

    if (ctrl == 0) return 0;

    reset(let);

    strlcpy(let->qid, qid, sizeof let->qid);

    p = ctrl;
    end = p + size;

    for (p = ctrl ; (p < end) && (q = memchr(p, '\n', end-p)); p = q+1) {
	switch (*p) {
	case C_FROM:		/* From: address */
		if (let->from)
		    freeaddress(let->from);
		if ( (let->from = calloc(1, sizeof let->from[0])) == 0 ) {
		    syslog(LOG_ERR, "out of memory");
		    abort();
		}
		if ( (let->from->full = restofline(1+p, q)) == 0) {
		    syslog(LOG_ERR, "out of memory");
		    abort();
		}
		let->from->domain = strdup(let->env->localhost);
		break;

	case C_TO:		/* To: address */
		memset(&to, 0, sizeof to);
		if ( (to.full = restofline(1+p, q)) == 0) {
		    syslog(LOG_ERR, "out of memory");
		    abort();
		}
		if ( ((sep = strchr(to.full, '|')) == 0) || (sep == to.full) ) {
		    syslog(LOG_ERR, "Qid %s: corrupted to address <%s>",
				    let->qid, to.full);
		    abort();
		}
		*sep++ = 0;
		to.domain = sep;

		if ( *to.domain == 0 ) {
		    syslog(LOG_ERR, "Qid %s: corrupted to address <%s>",
				    let->qid, to.full);
		    abort();
		}
		else if (newrecipient(&let->remote, &to,
				       emUSER, NOBODY_UID, NOBODY_GID) == -1)
		    abort();
		free(to.full);
		break;

	case C_FLAGS:		/* extra flags */
		switch (p[1]) {
		case 'H':   let->has_headers = 1;
			    break;
		case 'F':   let->mesgfrom = 1;
			    break;
		}
		break;

	case C_HEADER:		/* real headers live past here */
		if (1+q < end) {
		    let->headtext = restofline(1+q, end);
		    let->headsize = strlen(let->headtext);
		}
		else {
		    let->headtext = calloc(1,1);
		    let->headsize = 0;

		}
		munmap(ctrl,size);
		return 1;
	}
    }
    munmap(ctrl, size);
    return 0;
}


int
writecontrolfile(struct letter *let)
{
    FILE *f;
    char ctrlfile[sizeof(DATAPFX)+6+1];
    int count;
    enum r_status status;

    /* after writing the data, write the control file
     */
    sprintf(ctrlfile, CTRLPFX "%s", let->qid);

    if ( (f=fopen(ctrlfile, "w")) != 0) {
	/* queue comments always come first.
	 */
	if (let->qcomment && let->qcomment[0])
	    fprintf(f, "%c%s\n", C_STATUS, let->qcomment);
	
	if (notnull(let->from)) {
	    if (let->from->domain && strlen(let->from->domain) > 0)
		fprintf(f, "%c%s\n", C_FROM, let->from->full);
	    else
		fprintf(f, "%c%s@%s\n",C_FROM,let->from->user,
				    let->env->localhost);
	}

	for (count=let->remote.count; count-- > 0; ) {
	    status = let->remote.to[count].status;
	    if (status == PENDING || status == ACCEPTED) {
		fprintf(f, "%c%s|%s\n", C_TO, let->remote.to[count].fullname,
					      let->remote.to[count].host);
	    }
	}

	if (let->mesgfrom)
	    fprintf(f, "%cF ;has from:\n", C_FLAGS);

	/* additional headers ALWAYS come at the end of the
	 * control message so we can cheat and simply spool them
	 * off the disk.
	 */
	if ( let->has_headers ) {
	    fprintf(f, "%cH ;has headers\n", C_FLAGS);
	    fprintf(f, "%c%c ;additional headers\n", C_HEADER, C_HEADER);
	    addheaders(f, let);
	}

	if ( ferror(f) == 0 && fclose(f) == 0)
	    return 1;
	syslog(LOG_ERR, "can't write to controlfile: %m");
	fclose(f);
    }
    syslog(LOG_ERR, "can't save to controlfile: %m");
    return 0;
}


int
svspool(struct letter *let)
{
    /* mktemp() file format: fixed prefix, 6 X's, ob-null */
#define TEMPFILE DATAPFX "XXXXXX\0"

    char spoolfile[sizeof(TEMPFILE)];
    int retry = 10;

    /* No need to spool the file if it's only going to
     * local recipients
     */
    if (let->remote.count == 0) {
	unlink(let->tempfile);
	let->tempfile = 0;
	return 1;
    }

    /* after finishing the file, create the actual spoolfile
     * and rename the tempfile over to it.   Go around 10 times
     * if there's a race.
     */
    do {
	strcpy(spoolfile, TEMPFILE);

	if (mktemp(spoolfile) && (link(let->tempfile, spoolfile) == 0) )
	    break;
	if ( errno != EEXIST || retry <= 0) {
	    syslog(LOG_ERR, "can't save to spoolfile <%s -> %s>: %m",
			let->tempfile, spoolfile);
	    reset(let);
	    return 0;
	}
	sleep(1);
    } while (retry-- > 0);
    unlink(let->tempfile);
    let->tempfile = 0;

    strlcpy(let->qid, spoolfile+strlen(DATAPFX), sizeof let->qid);

    if (writecontrolfile(let) == 0) {
	unlink(spoolfile);
	return 0;
    }
    return 1;
}
