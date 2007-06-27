
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>

#if HAVE_MALLOC_H
#   include <malloc.h>
#else
#   include <stdlib.h>
#endif

#include "letter.h"
#include "usermap.h"

static char *
back(char *string, char *start, char c)
{
    --start;
    while ( (start >= string) && (*start != c))
	--start;
    return start;
}

static int
map(char *pat, char *string, struct address *try, struct passwd **mapuser)
{
    char *r, *p;

    if (string == 0 || pat == 0)
	return 0;

    while ( *string && *pat) {
	if (*pat == '*') {
	    while (*pat == '*')
		++pat;

	    if (*pat == 0)	/* tail match */
		return 1;

	    if (*pat == '~') {
		/* nasty slow username matcher */
		while (*string)
		    if (map(pat, string++, try, mapuser))
			return 1;
	    }
	    else {
		char *greed;

		for (greed = strrchr(string, *pat); greed >= string;
		                     greed = back(string,greed,*pat) ) {
		    if (map(pat, greed, try, mapuser))
			return 1;
		}
	    }
	    return 0;
	}
	else if (*pat == '~') {
	    char *uname;

	    if (*mapuser) return 0;	/* only one user allowed, sorry */

	    r = string;
	    while (isalnum(*string))
		++string;
	    if (string == r)
		return 0;
	    if ( (uname = alloca(1+(string-r))) == 0 )
		return 0;	/* need to throw a 4xx and die */

	    strncpy(uname, r, string-r);
	    uname[string-r] = 0;
	    if ( (*mapuser = getpwemail(try->dom, uname)) == 0 )
		return 0;
	    ++pat;
	}
	else if (*string++ != *pat++)
	    return 0;
    }

    return (*string == *pat);
}


char*
usermap(struct letter *let, struct address *try)
{
    struct passwd *mapuser  = 0;
    char *p, *q;
    char *cut;

    if ( !(let->env->usermap.pat && let->env->usermap.map) )
	return 0;

    if ( !map(let->env->usermap.pat, try->user, try, &mapuser) )
	return 0;

#if 0
    printf("%s -> %s", try->user, let->env->usermap.map);
    if (mapuser)
	printf(" (user = %s)", mapuser->pw_name);
    putchar('\n');
#endif

    if ( (cut = alloca(strlen(let->env->usermap.map)+1)) == 0 )
	return 0;	/* need to throw a 4xx and die */

    strcpy(cut, let->env->usermap.map);
    for ( p = strtok(cut, ","); p; p = strtok(NULL, ",") )
	if (p[0] == '~' && p[1] == '/') {
	    if ( mapuser && !isvhost(try->dom) ) {
		char *file = alloca(strlen(mapuser->pw_dir) + strlen(p+1) + 1);
		int ulen = strlen(try->user);
		char line[400];
		FILE *f;

		if ( file == 0 )
		    return 0;	/* need to throw a 4xx and die */
		strcpy(file, mapuser->pw_dir);
		strcat(file, p+1);

		if ( !goodfile(file, mapuser) )
		    continue;

		if ( f = fopen(file, "r") ) {
		    while (fgets(line, sizeof line, f)) {
			if ( strncmp(line, try->user, ulen) == 0
					    && line[ulen] == ':' ) {
			    fclose(f);
			    strtok(line, "\n");
			    if ( q = strdup(line+ulen+1) )
				return q;
			    return 0; /* need to throw a 4xx and die */
			}
		    }
		    fclose(f);
		}
	    }
	}
	else if ( q = strdup(p) )
	    return q;
	else
	    return 0; /* need to throw a 4xx and die */

    return 0;
}
