/*
 * local implementation of strlcpy(), for machines that don't have it.
 */

#include <string.h>

size_t
strlcpy(char *dest, char *src, size_t len)
{

    if ( src == 0 || dest == 0 || len == 0 ) return 0;
    
    strncpy(dest, src, len);
    dest[len-1] = 0;

    return strlen(src);		/* ugh */
}
