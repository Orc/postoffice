/*
Newsgroups: mod.std.unix
Subject: public domain AT&T getopt source
Date: 3 Nov 85 19:34:15 GMT

Here's something you've all been waiting for:  the AT&T public domain
source for getopt(3).  It is the code which was given out at the 1985
UNIFORUM conference in Dallas.  I obtained it by electronic mail
directly from AT&T.  The people there assure me that it is indeed
in the public domain.
*/

/*
 * modified 20-Feb-2006 for postoffice (opt; ==  rest of current argument
 * is optarg), and cripple ERR() so that it uses fprintf() to stderr. 
 */

/*LINTLIBRARY*/

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <stdlib.h>
#include <unistd.h>

#if HAVE_LIBGEN_H
#include <libgen.h>
#endif

#define ERR(s, c)	if(z_opterr){ fprintf(stderr, "%s%s%c\n", pgm, s, c); }

extern char *pgm;


int	z_opterr = 1;
int	z_optind = 1;
int	z_optopt;
char	*z_optarg;

int
z_getopt(argc, argv, opts)
int	argc;
char	**argv, *opts;
{
	static int sp = 1;
	register int c;
	register char *cp;

	if(sp == 1) {
		if(z_optind >= argc ||
		   argv[z_optind][0] != '-' || argv[z_optind][1] == '\0')
			return(EOF);
		else if(strcmp(argv[z_optind], "--") == 0) {
			z_optind++;
			return(EOF);
		}
	}

	z_optopt = c = argv[z_optind][sp];
	if(c == ':' || c == ';' || (cp=strchr(opts, c)) == 0) {
		ERR(": illegal option -- ", c);
		if(argv[z_optind][++sp] == '\0') {
			z_optind++;
			sp = 1;
		}
		return('?');
	}
	if(*++cp == ':') {
		if(argv[z_optind][sp+1] != '\0')
			z_optarg = &argv[z_optind++][sp+1];
		else if(++z_optind >= argc) {
			ERR(": option requires an argument -- ", c);
			sp = 1;
			return('?');
		} else
			z_optarg = argv[z_optind++];
		sp = 1;
	} else if (*cp == ';') {
		if (argv[z_optind][sp+1] != '\0')
			z_optarg = &argv[z_optind][sp+1];
		else
			z_optarg = 0;
		z_optind++;
		sp = 1;
	} else {
		if(argv[z_optind][++sp] == '\0') {
			sp = 1;
			z_optind++;
		}
		z_optarg = 0;
	}
	return(c);
}

#ifdef DEBUG

char *pgm;

void
quote(char *s, int mustquote)
{
    char *q;

    if (s == 0 || *s == 0) {
	if (mustquote)
	    puts("''");
	else
	    putchar('\n');
	return;
    }

    for (q=s; *q; ++q)
	if (!isalnum(*q))
	    break;

    if (*q) {
	putchar('\'');
	for (q=s; *q; ++q)
	    if (*q == '\'')
		printf("'\"'\"'");
	    else
		putchar(*q);
	putchar('\'');
	putchar('\n');
    }
    else
	puts(s);
}

long
main(int argc, char **argv)
{
    int c;
    char *optstr = argv[1];

#if HAVE_BASENAME
    pgm = basename(argv[0]);
#else
    {   char *avp = strrchr(argv[0], '/');
	pgm = avp ? (1+avp) : argv[0];
    }
#endif

    if (argc < 2) {
	fprintf(stderr, "usage: %s optstr [args]\n", pgm);
	exit(1);
    }
    ++argv, --argc;

    while ((c = z_getopt(argc, argv, optstr)) != EOF) {
	printf("-%c", c);
	quote(z_optarg, 0);
    }
    printf("--\n");
    argc -= z_optind;
    argv += z_optind;

    for (c=0; c < argc; c++)
	quote(argv[c], 1);

    exit(0);
}
#endif
