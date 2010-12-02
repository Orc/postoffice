#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#if HAVE_MALLOC_H
#   include <malloc.h>
#endif

#include "letter.h"
#include "mx.h"
#include "domain.h"
#include "public.h"

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
    char *q;
    int size;
    struct address *ret;

    if (full == 0)
	return 0;

    if ( (ret=calloc(sizeof *ret, 1)) && (ret->full = strdup(full)) ) {

	if ( q = strrchr(full, '@') ) {
	    ret->domain = strdup(q+1);
	    size = q-full;
	    if ( ret->domain && (ret->user = malloc(size+1)) ) {
		strncpy(ret->user, full, size);
		ret->user[size] = 0;
		return ret;
	    }
	}
	else if (q = strchr(full, '!')) {
	    ret->user = strdup(q+1);
	    size = q-full;
	    if ( ret->user && (ret->domain = malloc(size+1)) ) {
		strncpy(ret->domain, full, size);
		ret->domain[size] = 0;
		return ret;
	    }
	}
	else if ( (strlen(full) < 1) || (ret->user = strdup(full)) )
	    return ret;

    }
    freeaddress(ret);
    return 0;
}


static int
okayanyhow(struct env *env, int flags)
{
    return (flags & VF_FROM) ? (!env->verify_from) : env->forward_all;
}


int
localIP(ENV *e, struct ipa *a)
{
    /*ENV *e2 = e;
    struct ipa *a2 = a;*/
    struct in_addr *lip;

    if ( !a ) return 0;

    lip = e->local_if;
    while ( lip->s_addr ) {
	/*if ( e2 != e ) abort();
	if ( a2 != a ) abort();*/
	if ( (lip++)->s_addr == a->addr.s_addr )
	    return 1;
    }
    return 0;
}
		

struct address *
verify(struct letter *let, struct domain *dom, char *p, int flags, int *reason)
{
    char *e = p + strlen(p);
    int bad = 0;
    struct address *ret;
    extern char *addr(char*,int*);
    struct iplist mxes;
    int i;

    while ( (e > p) && (isspace(e[-1]) || e[-1] == '\r' || e[-1] == '\n') )
	--e;
    if (*e)
	*e = 0;

    if ((e > p) && (ret = mkaddress(addr(p, &bad))) ) {
	if (ret->domain) {
	    ret->local = 0;
	    /* check that there is an mx (or A record) for the mail domain;
	     * if that fails we fail unless verify_from is off and it's
	     * a MAIL FROM:<> address
	     */
	    if ( (getMXes(ret->domain, 1, &mxes) > 0) ) {
		for (i=0; i < mxes.count; i++)
		    if ( localIP(let->env, &mxes.a[i] ) ) {
			/* we are a legitimate mx for this address.
			 */
			ret->local = 1;
			if ( (i == 0) || !(let->env->mxpool) ) {
			    /* If we're not mxpooling, we handle mail for
			     * this domain locally, but if we are mxpooling
			     * we only handle the mail locally if we're the
			     * best mx for the domain
			     */
			    ret->deliver_here = 1;
			    ret->dom = getdomain(ret->domain);
			}
			break;
		    }
		freeiplist(&mxes);
	    }
	    else if ( !okayanyhow(let->env,flags) ) {
		if (reason) *reason = V_NOMX;
		freeaddress(ret);
		return 0;
	    }

	}
	else {
	    ret->deliver_here = ret->local = 1;
	    ret->dom = dom;
	}

	if (ret->deliver_here && (!userok(let,ret)) && (flags & VF_USER) ) {
	    if (reason) *reason = V_WRONG;
	    freeaddress(ret);
	    return 0;
	}
	return ret;
    }
    if (reason) { *reason = bad ? V_BOGUS : V_ERROR; }
    return 0;
}
