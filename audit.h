#ifndef _AUDIT_D
#define _AUDIT_D

#include "env.h"
#include "letter.h"

extern void audit(struct letter *, char *, char *, int);
extern void auditon(int);
extern void auditoff(int);

#endif/*_AUDIT_D*/
