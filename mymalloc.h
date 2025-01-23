#ifndef MYMALLOC_D
#define MYMALLOC_D

#ifdef DEBUG_MALLOC

void *mymalloc(size_t, char *, int);
void *myrealloc(void*, size_t, char *, int);
void *mycalloc(size_t, size_t, char *, int);
char *mystrdup(char*, char *, int);
int  myfree(void *, char *, int);

#define malloc(size)		mymalloc(size, __FILE__, __LINE__)
#define realloc(ptr,size)	myrealloc(ptr, size, __FILE__, __LINE__)
#define calloc(elements,size)	mycalloc(elements, size, __FILE__, __LINE__)
#define strdup(string)		mystrdup(string,__FILE__,__LINE__)
#define free(ptr)		myfree((ptr),__FILE__,__LINE__),((ptr)=0)

#endif


#ifdef AMALLOC

void *amalloc(size_t, char*, int);
void *arealloc(void*, size_t, char *, int);
void *acalloc(size_t, size_t, char *, int);
char *astrdup(char*, char*, int);
void  afree(void*, char*, int);

#define malloc(size)		amalloc(size, __FILE__, __LINE__)
#define realloc(ptr,size)	arealloc(ptr, size, __FILE__, __LINE__)
#define calloc(elements,size)	acalloc(elements, size, __FILE__, __LINE__)
#define strdup(string)		astrdup(string, __FILE__, __LINE__)
#define free(ptr)		afree(ptr,__FILE__,__LINE__)

#endif /*DEBUG_MALLOC||AMALLOC*/

#endif /*MYMALLOC_D*/
