/*
 * break arpa addresses out of a line (via RFC822)
 */
#include "config.h"
#include <stdio.h>
#include <ctype.h>

#if HAVE_ALLOCA_H
#   include <alloca.h>
#else
#   include <stdlib.h>
#endif


char *
arpatok(char **res)
{
    char *src, *dst, *ret;
    unsigned int quot = 0;
    unsigned int comment = 0;
    unsigned int broket = 0;
    unsigned char c;

    if (res == 0 || *res == 0 || **res == 0)
	return 0;

    src = ret = dst = *res;

    while (c = *src++) {
	if (c == '"')
	    quot = !quot;
	else if (c == '\\' && *src)
	    *dst++ = *src++;
	else if (!quot) {
	    if (c == '(') {
		for (comment=1; comment && *src; ++src) {
		    if (*src =='(') comment++;
		    else if (*src == ')') comment--;
		}
	    }
	    else if (c == ',')
		break;
	    else if (isspace(c))
		;
	    else if (c == '<') {
		if ( !broket ) {
		    broket = 1;
		    dst = ret;
		}
	    }
	    else if (broket && (c == '>')) {
		*dst++ = 0;
	    }
	    else  {
		*dst++ = c;
	    }
	}
	else
	    *dst++ = c;
    }
    *dst = 0;

    if (res) *res = c ? src : 0;

    return ret;
}

#if DEBUG


show(char *address)
{
    char *bfr = alloca(strlen(address)+1);
    char *q;

    strcpy(bfr, address);

    printf("[%s]\n", address);

    while ( q = arpatok(&bfr) )
	printf(" => %s\n", q);
}

main()
{
    show("orc@pell");
    show("orc(jessica parsons)@pell(.portland.or.us)");
    show(",orc(jessica parsons)@pell(.portland.or.us)");
    show("\"orc@pell.portland.or.us\"(jessica parsons)");
    show("orc,(jessica parsons)orc,orc(jessica parsons)@pell.portland.or.us");
    show("jessica parsons<orc@pell.portland.or.us>,orc@pell(<jessica@pell.portland.or.us>)");
    show("(jessica(parsons)<orc@tsfr.org>)<orc@pell.portland.or.us>orc@tsfr.org,root");
    show("<orc@pell.><orc@tsfr.org>jessica parsons");
    show("orc@pell\n"
	 "       <orc@tsfr.\n"
	 "        org>jessica parsons");
    show("");
    show(",");
    show(" (nothing but whitespace and comments here) ");
}
#endif
