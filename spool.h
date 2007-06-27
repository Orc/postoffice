#ifndef __SPOOL_D
#define __SPOOL_D

#include <stdio.h>
#include "letter.h"
#include "config.h"

#define DATAPFX		QUEUEDIR "dm"
#define CTRLPFX		QUEUEDIR "cm"
#define TEMPPFX		QUEUEDIR "tm"
#define	QRUNPFX		QUEUEDIR "xm"

#define C_TO		'T'	/* username on remote system */
#define C_FROM		'F'	/* MAIL FROM: */
#define C_STATUS	'S'	/* mail status (string) */
#define C_FLAGS		'!'	/* various header flags */
#define C_HEADER	'+'	/* headers to prefix the message with */

/* the following headers are obsolete */
#define C_HOST		'H'	/* host to send it to */
#define C_DATE		'D'	/* date the message was sent */


int   mkspool(struct letter *let);
int   svspool(struct letter *let);
int   examine(struct letter *let);

void receivedby(FILE *f, struct letter *let, struct recipient *to);
void addheaders(FILE *f, struct letter *let);
void   copybody(FILE *f, struct letter *let);

#endif/*__SPOOL_D*/
