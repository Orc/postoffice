#ifdef DEBUG_MALLOC

#ifndef MYMALLOC_D
#define MYMALLOC_D

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

#endif /*MYMALLOC_D*/

#endif /*DEBUG_MALLOC*/
