/*
 * debugging malloc()/realloc()/calloc()/free() that attempts
 * to keep track of just what's been allocated today.
 */
#ifndef AMALLOC_D
#define AMALLOC_D

extern char *astrdup(char*);
extern void *amalloc(int);
extern void *acalloc(int,int);
extern void *arealloc(void*,int);
extern void afree(void*);
extern void adump();

#define strdup(string)		astrdup(string)
#define malloc(sz)		amalloc(sz)
#define	calloc(count,size)	acalloc(count,size)
#define realloc(ptr, size)	arealloc(ptr, size)
#define free(size)		afree(size)

#endif/*AMALLOC_D*/
