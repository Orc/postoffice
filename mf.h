#ifndef __MF_D
#define __MF_D

#include "letter.h"


struct mfdata {
	int size;
	char data[1];
} ;


#define MF_OK		0		/* transaction ok */
#define MF_REJ		1		/* quietly reject transaction */
#define MF_REJ_CODE	2		/* reject transaction with message */
#define MF_TEMP		3		/* tempfail from non-soft milter */
#define MF_ERR		4		/* system error of some sort */
#define MF_EOF		5		/* a filter shut down */


/*
 * 2 kinds of filters;  a soft filter fails on;  if any of the transaction
 * EOFs, it shuts off and does not return an error status.  A hard filter
 * returns error statuses.
 *
 * filter=/path.to.socket
 * filter=host:port
 * filter.soft=/path.to.socket
 * filter.soft=host:port
 * filter.retry=(yes|no)   ! yes:  filter rejects cause 5xx responses.
 *			   ! no:   filter rejects cause 4xx responses.
 * 
 */
#ifdef WITH_MILTER
extern int mfregister(char* socket, char **opts);
extern int mfconnect(struct letter *let);
extern int mfhelo(struct letter *let, char *line);
extern int mffrom(struct letter *let, char *from);
extern int mfto(struct letter *let, char *to);
extern int mfdata(struct letter *let);
extern int mfreset(struct letter *let);
extern int mfquit(struct letter *let);
extern char *mfresult();
extern int mfcode();
#else
#define mfregister(x,y)	MF_OK
#define mfconnect(x) MF_OK
#define mfhelo(x,l) MF_OK
#define mffrom(x,f) MF_OK
#define mfto(x,t) MF_OK
#define mfdaya(x) MF_OK
#define mfreset(x) MF_OK
#define mfquit(x) MF_OK
#define mfresult() 0
#define mfcode() 0
#endif


extern void mfcomplain(struct letter *let, char *generic);


#endif/*__MF_D*/
