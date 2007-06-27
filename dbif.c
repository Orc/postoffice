#include "dbif.h"


#if HAVE_GDBM_H && !defined(DBM_SUFFIX)
#   define DBM_SUFFIX	".db"
#endif

DBhandle 
dbif_open(char *file, int flags, int mode)
{
#if HAVE_NDBM_H
    return (DBhandle)dbm_open(file, flags, mode);
#elif HAVE_GDBM_H
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

    return (DBhandle)gdbm_open(dbfile, 0, gflags, mode, 0);
#else
    return (DBhandle)0;
#endif
}


void
dbif_close(DBhandle db)
{
#if HAVE_NDBM_H
    dbm_close((DBM*)db);
#elif HAVE_GDBM_H
    gdbm_close((GDBM_FILE)db);
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

#if HAVE_NDBM_H
    value = dbm_fetch((DBM*)db,id);
#elif HAVE_GDBM_H
    value = gdbm_fetch((GDBM_FILE)db, id);
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

#if HAVE_NDBM_H
    return dbm_store(db,id,value,mode);
#elif HAVE_GDBM_H
    return gdbm_store(db,id,value,mode);
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

#if HAVE_NDBM_H
    return dbm_delete((DBM*)db, id);
#elif HAVE_GDBM_H
    return gdbm_delete((GDBM_FILE)db, id);
#else
    return -1;
#endif
}


int
dbif_rename(char *oldname, char *newname)
{
#if HAVE_NDBM_H || HAVE_GDBM_H
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

#if HAVE_GDBM_H
static datum ffn_key;
#endif


char *
dbif_findfirst(DBhandle db)
{
#if HAVE_NDBM_H
    datum key;
    key = dbm_firstkey(db);

    return key.dptr ? key.dptr : 0;
#elif HAVE_GDBM_H
    ffn_key =  gdbm_firstkey(db);

    return ffn_key.dptr ? ffn_key.dptr : 0;
#else
    return 0;
#endif
}


char *
dbif_findnext(DBhandle db, char *lastkey)
{
#if HAVE_NDBM_H
    datum key = dbm_nextkey(db);

    return key.dptr ? key.dptr : 0;
#elif HAVE_GDBM_H
    ffn_key = gdbm_nextkey(db,ffn_key);

    return ffn_key.dptr ? ffn_key.dptr : 0;
#else
    return 0;
#endif
}
