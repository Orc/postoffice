#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

#if HAVE_LIBGEN_H
#include <libgen.h>
#endif

#include "dbif.h"

static DBhandle  db = 0;
static char *dbname = 0;

int verbose = 0;

char *pgm;

void usage(char*,int);
void dbif_perror(char *);


int
create(int argc, char **argv, int mode)
{
    if (dbname) {
	fprintf(stderr, "%s: database %s already exists\n", pgm, dbname);
	return 2;
    }

    if (dbname == 0) {
	if (argc < 1)
	    usage("create", 1);
	else
	    dbname = argv[1];
    }

    if ( (db = dbif_open(dbname, mode, 0600)) == 0) {
	dbif_perror(dbname);
	return 1;
    }
    return 0;
}


int
clear(int argc, char **argv, int mode)
{
    if (dbname == 0) {
	if (argc < 1)
	    usage("clear", 1);
	else
	    dbname = argv[1];
    }

    if ( (db = dbif_open(dbname, DBIF_TRUNC|mode, 0600)) == 0 ) {
	dbif_perror(dbname);
	return 1;
    }
    return 0;
}


int
fetch(int argc, char **argv, int mode)
{
    int i;
    char *value;
    int found=0;

    if (argc < 1 || db == 0)
	usage("fetch", 1);

    for (i=1; i < argc; i++) {
	if ( value = dbif_get(db,argv[i]) ) {
	    printf("%s\n", value);
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
    char *key, *value;
    int rc = 0;

    if (db == 0 && argc > 0) {
	db = dbif_open(argv[1], mode, 0600);

	if (db == 0) {
	    dbif_perror(argv[1]);
	    return 2;
	}
    }

    for (key = dbif_findfirst(db); key; key = dbif_findnext(db,key)) {

	printf("%s", key);
	if ( value = dbif_get(db, key) ) {
	    printf("\t%s\n", value);
	}
	else {
	    printf(" ERROR %d\n", dbif_errno);
	    rc = 1;
	}
    }
    return rc;
}

static int
dbreopen(char *name, int mode)
{
    if (db) dbif_close(db);

    if ( (db = dbif_open(name, mode, 0600)) == 0 ) {
	dbif_perror(name);
	return 2;
    }
    return 0;
}

int
delete(int argc, char **argv, int mode)
{
    int i, rc = 0;

    if (dbname == 0)
	usage("delete", 1);
    else if ( (rc=dbreopen(dbname,mode)) != 0)
	return rc;

    for (i=1; i <argc; ++i) {
	if ( dbif_delete(db, argv[i]) != 0) {
	    dbif_perror(argv[i]);
	    rc = 1;
	}
    }
    return rc;
}


int
store(int argc, char **argv, int mode)
{
    int rc;
    int imode = (strcmp(argv[0], "insert") == 0) ? DBIF_INSERT : DBIF_REPLACE;

    if (dbname == 0)
	usage("insert", 1);
    else if ( (rc = dbreopen(dbname, mode)) != 0)
	return rc;

    if (dbif_put(db, argv[1], argv[2], imode) != 0) {
	dbif_perror(argv[1]);
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

	if (dbif_put(db, line, p, DBIF_INSERT) != 0) {
	    dbif_perror(line);
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
    { "clear",  clear,  DBIF_WRITER|DBIF_CREAT, "[database]" },
    { "create", create, DBIF_WRITER|DBIF_CREAT, "[database]" },
    { "delete", delete, DBIF_WRITER,            "key" },
    { "dump",   dump,   DBIF_READER,            "[database]" },
    { "fetch",  fetch,  DBIF_READER,            "key" },
    { "insert", store,  DBIF_WRITER,            "key value" },
    { "load",   load,   DBIF_WRITER|DBIF_CREAT, "[database]" },
    { "update", store,  DBIF_WRITER,            "key value" },
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
	dbif_close(db);
    exit(exitcode);
}

void
dbif_perror(char *text)
{
    /*dbif_error(db);*/
    perror(text);
}


main(int argc, char **argv)
{
    register opt;
    struct cmd *p;
    int status;

    opterr = 1;

#if HAVE_BASENAME
    pgm = basename(argv[0]);
#else
    {   char *avp = strrchr(argv[0], '/');
	pgm = avp ? (1+avp) : argv[0];
    }
#endif

    while ((opt = getopt(argc, argv, "?vd:")) != EOF)
	switch (opt) {
	case 'd':   db = dbif_open(dbname=optarg, DBIF_READER, 0600);
		    if (db == 0) {
			dbif_perror(optarg);
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
	dbif_close(db);
    exit(status);
}
