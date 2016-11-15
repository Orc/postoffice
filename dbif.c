#include "config.h"
#include "dbif.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#if HAVE_ALLOCA_H
#   include <alloca.h>
#endif


#if USE_GDBM && !defined(DBM_SUFFIX)
#   define DBM_SUFFIX	".db"
#endif

DBhandle 
dbif_open(char *file, int flags, int mode)
{
#if USE_GDBM
    int gflags = GDBM_READER;
    char *dbfile = alloca(strlen(file) + 1 + strlen(DBM_SUFFIX));

    if (dbfile == 0) return (DBhandle)0;

    strcpy(dbfile, file);
    strcat(dbfile, DBM_SUFFIX);

    if (flags & DBIF_TRUNC)
	gflags = GDBM_NEWDB;
    else if (flags & DBIF_CREAT)
	gflags = GDBM_WRCREAT;
    else if (flags & DBIF_WRITER)
	gflags = GDBM_WRITER;

    return gdbm_open(dbfile, 0, gflags, mode, 0);
#elif USE_NDBM
    return dbm_open(file, flags, mode);
#else
    return (DBhandle)0;
#endif
}


void
dbif_close(DBhandle db)
{
#if USE_GDBM
    gdbm_close(db);
#elif USE_NDBM
    dbm_close(db);
#endif
}



char *
dbif_get(DBhandle db, char *key)
{
    datum id, value;

    if (key) {
	id.dptr = key;
	id.dsize = strlen(key)+1;
    }
    else
	return 0;

#if USE_GDBM
    value = gdbm_fetch(db, id);
#elif USE_NDBM
    value = dbm_fetch(db,id);
#else
    return 0;
#endif

    return value.dptr ? value.dptr : 0;
}

int
dbif_put(DBhandle db, char *key, char *data, int mode)
{
    datum id, value;

    if (key && data) {
	id.dptr = key;
	id.dsize = strlen(key)+1;
	value.dptr = data;
	value.dsize = strlen(data)+1;
    }
    else
	return -1;

#if USE_GDBM
    return gdbm_store(db,id,value,mode);
#elif USE_NDBM
    return dbm_store(db,id,value,mode);
#else
    return -1;
#endif
}

int
dbif_delete(DBhandle db, char *key)
{
    datum id;

    id.dptr = key;
    id.dsize= strlen(key)+1;

#if USE_GDBM
    return gdbm_delete(db, id);
#elif USE_NDBM
    return dbm_delete(db, id);
#else
    return -1;
#endif
}


int
dbif_rename(char *oldname, char *newname)
{
#if USE_NDBM || USE_GDBM
    char *oldfile = alloca(strlen(oldname)+2+strlen(DBM_SUFFIX)),
	 *newfile = alloca(strlen(newname)+2+strlen(DBM_SUFFIX));

    if (oldfile == 0 || newfile == 0) return -1;

    strcpy(oldfile, oldname);
    strcat(oldfile, DBM_SUFFIX);
    strcpy(newfile, newname);
    strcat(newfile, DBM_SUFFIX);

    return rename(oldfile,newfile);
#else
    return -1;
#endif

}

#if USE_GDBM
static datum ffn_key;
#endif


char *
dbif_findfirst(DBhandle db)
{
#if USE_GDBM
    ffn_key =  gdbm_firstkey(db);

    return ffn_key.dptr ? ffn_key.dptr : 0;
#elif USE_NDBM
    datum key;
    key = dbm_firstkey(db);

    return key.dptr ? key.dptr : 0;
#else
    return 0;
#endif
}


char *
dbif_findnext(DBhandle db, char *lastkey)
{
#if USE_GDBM
    ffn_key = gdbm_nextkey(db,ffn_key);

    return ffn_key.dptr ? ffn_key.dptr : 0;
#elif USE_NDBM
    datum key = dbm_nextkey(db);

    return key.dptr ? key.dptr : 0;
#else
    return 0;
#endif
}
