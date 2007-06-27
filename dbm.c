#include <stdio.h>
#include <unistd.h>
#include <ndbm.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

static DBM  *db = 0;
static char *dbname = 0;

int verbose = 0;

char *pgm;

void usage(char*,int);
void dbm_perror(char *);


int
create(int argc, char **argv, int mode)
{
    if (dbname) {
	fprintf(stderr, "%s: database %s already exists\n", pgm, dbname);
	return 2;
    }

    if (dbname == 0)
	if (argc < 1)
	    usage("create", 1);
	else
	    dbname = argv[1];

    if ( (db = dbm_open(dbname, mode, 0600)) == 0) {
	dbm_perror(dbname);
	return 1;
    }
    return 0;
}


int
clear(int argc, char **argv, int mode)
{
    char *fqdbname;

    if (dbname == 0)
	if (argc < 1)
	    usage("clear", 1);
	else
	    dbname = argv[1];

    if ( (fqdbname = alloca(strlen(dbname) + 2 + sizeof(DBM_SUFFIX))) == 0) {
	perror(dbname);
	return 2;
    }
    sprintf(fqdbname, "%s%s", dbname, DBM_SUFFIX);
    if (unlink(fqdbname) != 0) {
	perror(dbname);
	return 2;
    }
    if ( (db = dbm_open(dbname, mode, 0600)) == 0 ) {
	dbm_perror(dbname);
	return 1;
    }
    return 0;
}


int
fetch(int argc, char **argv, int mode)
{
    int i;
    datum key, value;
    int found=0;

    if (argc < 1 || db == 0)
	usage("fetch", 1);

    for (i=1; i < argc; i++) {
	key.dptr = argv[i];
	key.dsize = strlen(argv[i])+1;

	value = dbm_fetch(db, key);

	if (value.dptr) {
	    printf("%.*s\n", value.dsize, value.dptr);
	    found++;
	}
    }
    if (found == argc)
	return 0;
    if (found == 0)
	return 2;
    return 1;
}


int
dump(int argc, char **argv, int mode)
{
    datum key, value;
    int rc = 0;

    if (db == 0 && argc > 0) {
	db = dbm_open(argv[1], mode, 0600);

	if (db == 0) {
	    dbm_perror(argv[1]);
	    return 2;
	}
    }

    for (key = dbm_firstkey(db); key.dptr; key = dbm_nextkey(db)) {

	printf("%.*s", key.dsize, key.dptr);
	if (verbose)
	    printf("(%d)", key.dsize);
	value = dbm_fetch(db, key);

	if (value.dptr) {
	    printf("\t%.*s", value.dsize, value.dptr);
	    printf(verbose ? "(%d)\n" : "\n", value.dsize);
	}
	else {
	    printf(" ERROR %d\n", dbm_error(db));
	    rc = 1;
	}
    }
    return rc;
}

static int
dbreopen(char *name, int mode)
{
    if (db) dbm_close(db);

    if ( (db = dbm_open(name, mode, 0600)) == 0 ) {
	dbm_perror(name);
	return 2;
    }
    return 0;
}

int
delete(int argc, char **argv, int mode)
{
    datum key;
    int i, rc;

    if (dbname == 0)
	usage("delete", 1);
    else if ( (rc=dbreopen(dbname,mode)) != 0)
	return rc;

    for (i=1; i <argc; ++i) {
	key.dptr = argv[i];
	key.dsize = strlen(argv[i])+1;
	if ( dbm_delete(db, key) != 0) {
	    dbm_perror(argv[i]);
	    rc = 1;
	}
    }
    return rc;
}


int
store(int argc, char **argv, int mode)
{
    datum key, value;
    int rc;
    int imode = (strcmp(argv[0], "insert") == 0) ? DBM_INSERT : DBM_REPLACE;

    if (dbname == 0)
	usage("insert", 1);
    else if ( (rc = dbreopen(dbname, mode)) != 0)
	return rc;

    key.dptr = argv[1];
    key.dsize = strlen(argv[1])+1;
    value.dptr = argv[2];
    value.dsize = strlen(argv[2])+1;

    if (dbm_store(db, key, value, imode) != 0) {
	dbm_perror(argv[1]);
	return 1;
    }
    return 0;
}


int
load(int argc, char **argv, int mode)
{
    int rc;
    char line[1024];
    char *p;
    char *q;
    datum key, value;
    int opt;

    if ( (rc = clear(argc, argv, mode)) != 0)
	return rc;

    while (fgets(line, sizeof line, stdin)) {
	/* skip comment lines */
	if (line[0] == '#')
	    continue;
	if ( (q = strchr(line, '\n')) != 0)
	    *q = 0;

	if ( (p = strchr(line, '\t')) != 0) {
	    *p++ = 0;
	    while (isascii(*p) && isspace(*p))
		++p;
	}

	key.dptr = line;
	key.dsize = strlen(line)+1;

	value.dptr  = p ? p : "";
	value.dsize = p ? strlen(p)+1 : 0;

	if (dbm_store(db, key, value, DBM_INSERT) != 0) {
	    dbm_perror(line);
	    rc = 1;
	}
    }
    return rc;
}


struct cmd {
    char *cmd;
    int (*func)(int,char**, int);
    int openmode;
    char *usage;
} cmds[] = {
    { "clear",  clear,  O_RDWR|O_CREAT, "[database]" },
    { "create", create, O_RDWR|O_CREAT|O_EXCL, "[database]" },
    { "delete", delete, O_RDWR,         "key" },
    { "dump",   dump,   O_RDONLY,       "[database]" },
    { "fetch",  fetch,  O_RDONLY,       "key" },
    { "insert", store,  O_RDWR,         "key value" },
    { "load",   load,   O_RDWR|O_CREAT, "[database]" },
    { "update", store,  O_RDWR,         "key value" },
};

#define NRCMDS (sizeof cmds / sizeof cmds[0])


void
usage(char *cmd, int exitcode)
{
    register i;
    struct cmd *p;
    char *pfx = "", *opt = "";
    int pfxlen;

    if (cmd == 0) {
	fprintf(stderr, "usage: %s [-d database] cmd args\n", pgm);
        pfx = "";
	pfxlen = strlen(pgm) + 21;
    }
    else {
	pfxlen = strlen(pgm);
	pfx = pgm;
	opt = "-d database ";
    }

    for (p=cmds+0, i=NRCMDS; i-- > 0; p++ ) {
	if (cmd == 0 || strcmp(cmd, p->cmd) == 0)
	    fprintf(stderr, "%*s %s%s %s\n", pfxlen,pfx, opt, p->cmd, p->usage);
    }

    if (db)
	dbm_close(db);
    exit(exitcode);
}

void
dbm_perror(char *text)
{
    /*dbm_error(db);*/
    perror(text);
}


main(int argc, char **argv)
{
    register opt;
    struct cmd *p;
    int status;

    opterr = 1;

    pgm = basename(argv[0]);

    while ((opt = getopt(argc, argv, "?vd:")) != EOF)
	switch (opt) {
	case 'd':   if ( (db = dbm_open(dbname=optarg, O_RDONLY, 0600)) == 0 ) {
			dbm_perror(optarg);
			exit(1);
		    }
		    break;
	case 'v':   verbose = 1;
		    break;
	default:    usage(0, opt == '?');
	}
    argc -= optind;
    argv += optind;

    if (argc < 1)
	usage(0, 1);

    for (p=cmds+0, opt=NRCMDS; opt-- > 0; p++)
	if (strcasecmp(argv[0], p->cmd) == 0)
	    break;

    if (opt < 0)
	usage(0, 1);

    status = (*p->func)(argc, argv, p->openmode);
    if (db)
	dbm_close(db);
    exit(status);
}
