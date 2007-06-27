#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <sysexits.h>

#include "spool.h"

int
Qpicker(const struct dirent *f)
{
    return (f->d_name[0] == 'c') && (f->d_name[1] == 'm') && (f->d_namlen == 8);
}

static int
Qcompare(const struct dirent *a, const struct dirent *b)
{
    struct stat sa, sb;
    int  ra, rb;

    ra = stat(a->d_name, &sa);
    rb = stat(b->d_name, &sb);

    if (ra == -1)
	return (rb == -1) ? 0 : 1;
    else if (rb == -1)
	return -1;

    return sa.st_ctime - sb.st_ctime;
}

static char *
unit(off_t size)
{
    static char fmt[15];

    if (size < 10000)
	sprintf(fmt, "%ld ", size);
    else if (size < 1000000)
	sprintf(fmt, "%5.2fK", ((float)size)/1024.0);
    else if (size < 1000000000)
	sprintf(fmt, "%5.2fM", (float)(size/1024)/1024.0);
    else
	sprintf(fmt, "%5.2fG", (float)(size/(1024*1024))/1024.0);
    return fmt;
}


#define TFMT	"%8s %8s %17s %s"
#define FFMT	"%35s %s%c"
#define CFMT	"%17s %.62s"

void
listq()
{
    struct dirent **qf;
    int count;
    FILE *f;
    char df[9];
    char qid[10];
    char xf[9];
    char line[80];
    char comment[200];
    char date[40];
    struct stat st;
    struct dirent *q;
    int i;

    if (chdir(SPOOLDIR) || (count = scandir(".", &qf, Qpicker, Qcompare)) < 0) {
	perror(SPOOLDIR);
	exit(EX_NOPERM);
    }

    if (count == 0) {
	puts("Mail queue is empty.");
	exit(EX_OK);
    }

    printf("   Mail Queue (%d request%s)\n", count, (count!=1)?"s":"");
    printf(" --ID--  --Size-- -----Queued------ ------Sender/Recipient------\n");

    for (i=0; count-- > 0; ++i) {
	strcpy(df, qf[i]->d_name);
	df[0] = 'd';
	strcpy(xf, qf[i]->d_name);
	xf[0] = 'x';

	if (stat(df, &st) != 0) {
	    printf("%6s (no data file)\n", df+2);
	    continue;
	}

	if ( (f = fopen(qf[i]->d_name, "r")) == 0 ) {
	    printf("%6s (no control file)\n", df+2);
	    continue;
	}

	comment[0] = 0;
	while ( fgets(line, sizeof line, f) != 0 )
	    if (line[0] == C_STATUS)
		strncpy(comment, line+1, sizeof(comment)-2);
	    else if (line[0] == C_FROM || line[0] == C_HEADER)
		break;

	if (line[0] != C_FROM)
	    sprintf(line, "%c<>\n", C_FROM);

	strftime(date, 40, "%H:%M %d-%b-%Y", localtime(&st.st_ctime));

	sprintf(qid, (access(xf,R_OK) == 0) ? "*%6s*" :" %6s ", df+2);

	printf(TFMT, qid, unit(st.st_size), date, line+1);
	if (comment[0])
	    printf(CFMT, "", comment);

	rewind(f);
	while ( fgets(line, sizeof line, f) != 0 && line[0] != C_HEADER)
	    if (line[0] == C_TO) {
		char *p = strchr(line, '|');

		if (p) {
		    *p = 0;
		    printf(FFMT, "", line+1, '\n');
		}
		else {
		    printf(FFMT, "", line+1, 0);
		}
	    }
	fclose(f);
    }
    exit(EX_OK);
}
