#ifndef __MF_D
#define __MF_D

#include "config.h"
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
extern void mfcomplain(struct letter *let, char *generic);
extern void mflist(FILE*,int);

#elif GCC_NOT_C

static inline int ___trick(int x) { return x; }
#define mfregister(x,y)	___trick(MF_OK)
#define mfconnect(x) ___trick(MF_OK)
#define mfhelo(x,l) ___trick(MF_OK)
#define mffrom(x,f) ___trick(MF_OK)
#define mfto(x,t) ___trick(MF_OK)
#define mfdaya(x) ___trick(MF_OK)
#define mfreset(x) ___trick(MF_OK)
#define mfquit(x) ___trick(MF_OK)
#define mfresult() ___trick(0)
#define mfcode() ___trick(0)
#define mfcomplain(l,g) ___trick(0)
#define mflist(f,i) ___trick(0)

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
#define mfcomplain(l,g) 0
#define mflist(f,i) 0

#endif


#endif/*__MF_D*/
