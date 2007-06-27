#ifndef _DBIF_D
#define _DBIF_D

#include "config.h"
#include <errno.h>

#if HAVE_NDBM_H
#   include <sys/types.h>
#   include <sys/stat.h>
#   include <fcntl.h>
#   include <ndbm.h>

typedef DB * DBhandle;

#define DBIF_READER	O_RDONLY
#define DBIF_WRITER	O_RDWR
#define DBIF_CREAT	O_CREAT
#define DBIF_TRUNC	O_TRUNC|O_CREAT

#define DBIF_REPLACE	DBM_REPLACE
#define DBIF_INSERT	DBM_INSERT

#define dbif_errno	errno

#elif HAVE_GDBM_H
#   include <gdbm.h>

typedef GDBM_FILE DBhandle;

#define DBIF_READER	0x00
#define DBIF_WRITER	0x01
#define DBIF_CREAT	0x10	/* "gdbm_wrcreat" */
#define DBIF_TRUNC	0x20	/* "gdbm_newdb" */

#define	DBIF_REPLACE	GDBM_REPLACE
#define DBIF_INSERT	GDBM_INSERT

#define dbif_errno	gdbm_errno

#else
#   error "Can't build postoffice without ndbm"
#endif

DBhandle	dbif_open(char*, int, int);
void		dbif_close(DBhandle);
char*		dbif_get(DBhandle, char*);
int		dbif_put(DBhandle, char*, char*,int);
int		dbif_delete(DBhandle, char*);
int		dbif_rename(char*,char*);

char*		dbif_findfirst(DBhandle);
char*		dbif_findnext(DBhandle,char*);

#endif/*_DBIF_D*/
