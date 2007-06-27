#include <stdio.h>
#include <malloc.h>
#include <string.h>

#include "letter.h"
#include "mx.h"

void
freeaddress(struct address *ptr)
{
    if (ptr) {
	if (ptr->domain) free(ptr->domain);
	if (ptr->user) free(ptr->user);
	if (ptr->full) free(ptr->full);
	if (ptr->alias) free(ptr->alias);
	free(ptr);
    }
}


struct address *
mkaddress(char *full)
{
    struct address *ret;
    char *q;

    if (full == 0)
	return 0;

    if ( (ret=calloc(1,sizeof *ret)) && (ret->full = strdup(full)) ) {

	if ( q = strrchr(full, '@') ) {
	    ret->domain = strdup(q+1);
	    if ( ret->domain && (ret->user = malloc(q-full)) ) {
		memcpy(ret->user, full, q-full);
		ret->user[q-full] = 0;
		return ret;
	    }
	}
	else if (q = strchr(full, '!')) {
	    ret->user = strdup(q+1);
	    if ( ret->user && (ret->domain = malloc(q-full)) ) {
		memcpy(ret->domain, full, q-full);
		ret->domain[q-full] = 0;
		return ret;
	    }
	}
	else if ( (strlen(full) < 1) || (ret->user = strdup(full)) )
	    return ret;

    }
    freeaddress(ret);
    return 0;
}


struct address *
verify(struct letter *let, char *p, int user_validate, int *reason)
{
    char *e = p + strlen(p);
    int bad = 0;
    struct address *ret;
    extern char *addr(char*,int*);
    struct iplist mxes;
    int i;
    struct in_addr *lip;

    while ( (e > p) && (isspace(e[-1]) || e[-1] == '\r' || e[-1] == '\n') )
	--e;
    if (*e)
	*e = 0;

    if ((e > p) && (ret = mkaddress(addr(p, &bad))) ) {
	if (ret->domain) {
	    if (getMXes(ret->domain, &mxes) <= 0) {
		if (reason) *reason = V_NOMX;
		freeaddress(ret);
		return 0;
	    }
	    ret->local = 0;
	    for (lip=let->env->local_if; lip->s_addr; lip++)
		for (i=0; i < mxes.count; i++)
		    if (lip->s_addr == mxes.a[i].addr.s_addr) {
			/* we are a legitimate mx for this address.
			 */
			ret->local = 1;
			break;
		    }
	    freeiplist(&mxes);

	}
	else
	    ret->local = 1;


	if (ret->local && user_validate && !userok(let, ret)) {
	    if (reason) *reason = V_WRONG;
	    freeaddress(ret);
	    return 0;
	}

	return ret;
    }
    if (reason) { *reason = bad ? V_BOGUS : V_ERROR; }
    return 0;
}
