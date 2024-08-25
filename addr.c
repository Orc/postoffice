#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>

#include "mymalloc.h"

char *
addr(char *p, int *bad)
{
    char *ret;
    char *q;
    int quot = 0,
	brok = 0;

    *bad = 0;
    if ( (q=ret=strdup(p)) == 0)
	return 0;

    *bad = 1;
    /* normalize the address by destringing and clipping around <>'s
     */
    for ( ;*p ; ++p) {
	if (brok && *p == '>') {
	    *q = 0;
	    break;
	}
	else if (*p == '"') {
	    quot = !quot;
	    continue;
	}
	else if ( (*p == '\\') && p[1]) {
	    ++p;
	}
	else if ( !quot ) {
	    if (*p == '<' && !brok) {
		brok = 1;
		q = ret;
		continue;
	    }
	    else if (isspace(*p)) {
		free(ret);
		return 0;
	    }
	}
	*q++ = *p;
    }
    while (q > ret && (q[-1] == '\r' || q[-1] == '\n'))
	--q;
    *q = 0;

    /* check for disallowed characters
     */
    for (p = ret; *p; ++p) {
	if ( (*p < ' ') || strchr(" ()<>{}:;", *p)) {
	    free(ret);
	    return 0;
	}
    }
    return ret;
}


#if DEBUG_ADDR

say(char *line)
{
    char *ret;
    int bad;

    ret = addr(line, &bad);

    if (ret) {
	printf("%s -> %s\n", line, ret);
	free(ret);
    }
    else
	printf("%s !! %s\n", line, bad ? "parse error" : strerror(errno));


}

main()
{
    say("orc");
    say("<orc>");
    say("<\"orc\">");
    say("\"<orc\">");
    say("<\"o\"\"rc\">");
    say("david parsons<orc>");
    say("\"david parsons\"<orc>");
    say("<>");
    say("");
}
#endif
