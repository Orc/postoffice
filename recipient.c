#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>
#include <syslog.h>

#if HAVE_MALLOC_H
#   include <malloc.h>
#endif
#if HAVE_ALLOCA_H
#   include <alloca.h>
#endif

#include "letter.h"
#include "mymalloc.h"

struct back {
    char *user;
    struct domain *dom;
    struct back *next;
};

int
newrecipient(struct list *list,
             struct address *to,
	     enum r_type typ,
	     uid_t uid,
	     gid_t gid)
{
    struct recipient *new;
    int i;


    if ( (i=list->count) > 0)
	for (new = list->to + 0; i-- > 0; ++new)
	    if (strcmp(to->full, new->fullname) == 0 && typ == new->typ
						     && uid == new->uid)
		return list->count;

    if (list->count >= list->size) {
	list->size = list->count+10;
	list->to = list->to ? realloc(list->to, sizeof(*new) * list->size)
		            : malloc(sizeof(*new) * list->size);

	if (list->to == 0) {
	    list->size = 0;
	    return -1;
	}
    }

    new = list->to + list->count;
    new->host = new->user = 0;
    new->status = PENDING;

    if ( (new->fullname = strdup(to->full)) == 0)
	return -1;
    if (to->domain && (new->host = strdup(to->domain)) == 0) {
	free(new->fullname);
	return -1;
    }
    if (to->user && (new->user = strdup(to->user)) == 0) {
	free(new->fullname);
	free(new->host);
	return -1;
    }
    new->dom = to->dom;
    new->uid = uid;
    new->gid = gid;
    new->typ = typ;
    list->count++;
    return list->count;
}

int localprocess(struct letter *, struct address *, struct back*);
int expand(struct letter *,
           struct back *,
	   struct address *,
	   char *,
	   char *(*)(char **),
	   uid_t,
	   gid_t,
	   int);

static char *
token(char **cpp)
{
    char *p;
    char *begin, *q;
    int quot=0;


    if (cpp == 0 || *cpp == 0 || **cpp == 0)
	return 0;
    p = (*cpp);

    begin = q = p;

    while (*p && ( quot || *p != ',') ) {
	if (*p == '"') {
	    quot = !quot;
	    ++p;
	    continue;
	}
	else if (*p == '\\' && p[1] != 0)
	    ++p;
	else if (!quot && isspace(*p)) {
	    p++;
	    continue;
	}

	if (p > q) *q = *p;
	q++, p++;
    }
    if (*p) { *p++ = 0; }
    *cpp = p;

    *q = 0;

    return begin;
}


int
recipients(struct letter *let, struct address *to)
{
    if (to->alias)
	return expand(let, 0, to, to->alias, 0, NOBODY_UID, NOBODY_GID, 1);
    else if (to->deliver_here)
	return localprocess(let, to, 0);
    else 
	return newrecipient(&let->remote, to, emUSER, NOBODY_UID, NOBODY_GID);
}


int
localprocess(struct letter *let, struct address *u, struct back *b)
{
    struct email *em = getemail(u);

    if (let == 0)
	return -1;
    if (em == 0)
	return let->local.count;

    if (em->forward)
	return expand(let, b, u, em->forward, token, em->uid, em->gid, 0);
    return newrecipient(&let->local, u, emUSER, em->uid, em->gid);
}


int
expand(struct letter *let,
       struct back *prev,
       struct address *who,
       char *line,
       char *(*chop)(char**),
       uid_t uid,
       gid_t gid,
       int alias)
{
    struct back link;
    char *word;
    int rc = 0;
    int count = 0;
    char *bfr = alloca(strlen(line)+1);
    struct address addr;

    strcpy(bfr, line);

    if (chop == 0) chop = token;

    for (word = (*chop)(&bfr); word; word = (*chop)(&bfr)) {
	bzero(&addr, sizeof addr);
	addr.full = word;
	addr.user = who->user;
	addr.domain = who->domain;
	addr.dom = who->dom;
	if (*word == '/') {
	    if (uid == 0)
		syslog(LOG_ERR, "uid 0 cannot write to file %s", 1+word);
	    else
		rc = newrecipient(&let->local, &addr, emFILE, uid, gid);
	}
	else if (*word == '|') {
	    if (uid == 0)
		syslog(LOG_ERR, "uid 0 cannot execute %s", 1+word);
	    else
		rc = newrecipient(&let->local, &addr, emEXE, uid, gid);
	}
	else if (strncmp(word, ":include:/", 10) == 0) {
	    if (alias) {
		FILE *f;
		char line[200];

		if (f = fopen(9+word, "r")) {
		    while (fgets(line, sizeof line, f)) {
			rc = expand(let,prev,who,line,token,uid,gid,alias);
			if (rc < 0)
			    break;
		    }
		    fclose(f);
		}
	    }
	    else
		syslog(LOG_ERR, ":include: only works from /etc/aliases");

	}
	else {
	    struct address *p;
	    struct back *q;


	    if ( (p = verify(let,who->dom,word,VF_USER,(void*)0)) == 0)
		rc = 0;
	    else {
		link.next = prev;
		link.user = p->user;
		link.dom  = p->dom;

		for (q = prev; q; q = q->next)
		    if ( (p->dom == q->dom) && (strcmp(q->user, p->user) == 0) )
			break; /* alias loop */

		if (q) {
		    struct back *link = prev;
		    int sz = strlen(username(p->dom, p->user));
		    char *msg;
		    char *what = p->alias ? "alias" : "forward";

		    if (q != prev) {
			for ( ;link != q; link = link->next)
			    sz += 3+strlen(username(link->dom,link->user));

			if (msg = alloca(sz)) {
			    strcpy(msg, username(p->dom, p->user));
			    for (link = prev ; link != q; link = link->next) {
				strcat(msg,"->");
				strcat(msg,username(link->dom,link->user));
			    }
			    strcat(msg,"->");
			    strcat(msg, username(link->dom,link->user));
			    syslog(LOG_ERR, "%s loop %s", what, msg);
			}
			else
			    syslog(LOG_ERR, "%s loop for %s", what, word);
		    }
		    if (!p->alias)
			rc = newrecipient(&let->local, p, emUSER, uid, gid);
		}
		else if (p->alias) {
		    rc = expand(let,&link,p,p->alias,token,uid,gid,alias);
		}
		else if (p->deliver_here) {
		    rc = localprocess(let,p,&link);
		}
		else
		    rc = newrecipient(&let->remote,p,emUSER,uid,gid);
		freeaddress(p);
	    }
	}
	if (rc < 0)
	    return rc;
	count += rc;
    }
    return count;
}


void
freelist(struct list *p)
{
    int i;

    for (i=p->count; i-- > 0; ) {
	if (p->to[i].fullname) free(p->to[i].fullname);
	if (p->to[i].user) free(p->to[i].user);
	if (p->to[i].host) free(p->to[i].host);
    }
    p->count = 0;
}
