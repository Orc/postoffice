#include "config.h"

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
#if HAVE_ALLOCA_H
#   include <alloca.h>
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
    char *r;

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

	    strlcpy(uname, r, string-r);
	    if ( (*mapuser = getpwemail(try->dom, uname)) == 0 )
		return 0;
	    ++pat;
	}
	else if (*string++ != *pat++)
	    return 0;
    }

    return (*string == *pat);
}


static char*
expandmap(struct usermap *um, struct address *try, struct passwd *user)
{
    char *p;
    char *cut;

    if ( (cut = alloca(strlen(um->map)+1)) == 0 )
	return 0;	/* need to throw a 4xx and die */

    strcpy(cut, um->map);
    for ( p = strtok(cut, ","); p; p = strtok(NULL, ",") )
	if ( (p[0] == '~') && user) {
	    if (p[1] == 0)
		return strdup(user->pw_name);
	    else if ( p[1] == '/' && !isvhost(try->dom) ) {
		char *file = alloca(strlen(user->pw_dir) + strlen(p+1) + 1);
		int ulen = strlen(try->user);
		char line[400];
		FILE *f;

		if ( file == 0 )
		    return 0;	/* need to throw a 4xx and die */
		strcpy(file, user->pw_dir);
		strcat(file, p+1);

		if ( !goodfile(file, user) )
		    continue;

		if ( f = fopen(file, "r") ) {
		    while (fgets(line, sizeof line, f)) {
			if ( strncasecmp(line, try->user, ulen) == 0
						&& line[ulen] == ':' ) {
			    fclose(f);
			    strtok(line, "\n");
			    return strdup(line+ulen+1);
			}
		    }
		    fclose(f);
		}
	    }
	}
	else
	    return strdup(p);
    return 0;
}


char*
usermap(struct letter *let, struct address *try)
{
    struct passwd *mapuser;
    struct usermap *um;


    for (um = let->env->usermap; um; um = um->next) {
	mapuser = 0;
	if ( map(um->pat, try->user, try, &mapuser) )
	    return expandmap(um, try, mapuser);
    }
    return 0;
}
