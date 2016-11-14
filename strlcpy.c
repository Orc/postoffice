/*
 * local implementation of strlcpy(), for machines that don't have it.
 */
#include <stdio.h>
#include <string.h>

size_t
strlcpy(char *dest, char *src, size_t len)
{

    if ( src == 0 || dest == 0 || len == 0 ) return 0;
    
    strncpy(dest, src, len);
    dest[len-1] = 0;

#if AAIIEE
    fprintf(stderr, "strlcpy: \"%s\" -> \"%s\" (%d)\n", src, dest, len);
#endif

    return strlen(src);		/* ugh */
}


#if TEST

static void
result(char *dest, char *src, size_t len)
{

    size_t res = strlcpy(dest, src, len);

    if ( src )
	printf("strlcpy(%p,\"%s\",%d)", dest, src, len);
    else
	printf("strlcpy(%p,null,%d)", dest, len);

    printf(" = %d", res);
    if ( dest && res )
	printf(" \"%s\"", dest);
    putchar('\n');
}

int
main()
{
    char dest[10];

    result(dest, 0, sizeof dest);
    result(0,    "abc", 100);
    result(dest, "abc", 0);
    result(0,    0,     0);
    result(0,    0,     100);
    
    result(dest, "abc", sizeof dest);
    result(dest, "a super super super super long string", sizeof dest);

    return 0;
}
#endif/*TEST*/
