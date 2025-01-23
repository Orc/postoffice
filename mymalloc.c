#include <stdlib.h>
#include <syslog.h>
#include <string.h>

#ifdef AMALLOC
#include "amalloc.h"
#endif

#ifdef DEBUG_MALLOC

void *
mymalloc(size_t size, char *file, int line)
{
    void *ptr;

    if ( ptr = malloc(size) )
	syslog(LOG_DEBUG, "debug: malloc %d bytes (%p) at %s:%d", size, ptr, file, line);
    else
	syslog(LOG_DEBUG, "debug: malloc(%d) failed at %s:%d", size, file, line);
    return ptr;
}

void *
myrealloc(void *orig, size_t size, char *file, int line)
{
    void *ptr;

    if ( ptr = realloc(orig, size) )
	syslog(LOG_DEBUG, "debug: realloc %d bytes (%p) at %s:%d", size, ptr, file, line);
    else
	syslog(LOG_DEBUG, "debug: realloc(%p,%d) failed at %s:%d", orig, size, file, line);
    return ptr;
}

void *
mycalloc(size_t elements, size_t size, char *file, int line)
{
    void *ptr;

    if ( ptr = calloc(elements, size) )
	syslog(LOG_DEBUG, "debug: calloc %ld bytes (%p) at %s:%d", elements*size, ptr, file, line);
    else
	syslog(LOG_DEBUG, "debug: calloc(%d,%d) failed at %s:%d", elements, size, file, line);
    return ptr;
}

char *
mystrdup(char *string, char *file, int line)
{
    char *ptr;

    if ( ptr = strdup(string) )
	syslog(LOG_DEBUG, "debug: strdup <%s> (%p) at %s:%d", string, string, file, line);
    else
	syslog(LOG_DEBUG, "debug: strdup failed at %s:%d", file, line);
    return ptr;
}


int
myfree(void *ptr, char *file, int line)
{
    if ( ptr ) {
	syslog(LOG_DEBUG, "debug: free (%p) at %s:%d", ptr, file, line);
	free(ptr);
    }
    else
	syslog(LOG_DEBUG, "debug: trying to free a null pointer at %s:%d", file, line);
    return 42;
}

#endif /*DEBUG_MALLOC*/
