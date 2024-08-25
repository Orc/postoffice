#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <syslog.h>

#if HAVE_CRYPT_H
#include <crypt.h>
#endif

#include "letter.h"
#include "dbif.h"
#include "audit.h"
#include "mymalloc.h"

/*
 * C:AUTH LOGIN
 * 334 b64'Username:
 * C:b64'<username>
 * 334 b64'Password:
 * C:b64'<password>
 * 235 Pass, friend.
 * 
 * C:AUTH LOGIN b64'<username>
 * 334 b64'Password:
 * C:b64'<password>
 * 235 Pass, friend.
 */

extern char *from64(char*);
extern char *to64(char*);

#if WITH_PAM
extern int pam_login_ok(char*,char*,char*);
#endif


/*
 * authmeharder() verifies a user/passwd.
 */
static int
authmeharder(struct letter *let, char *user, char *pass)
{
    struct address *addr;
    struct passwd *pw;
    char *encrypted;
    int ret = 0;


    if ( !(let && user && pass) )
	return 1;


    if ( addr = mkaddress(user) ) {


	if ( addr->user ) { 
	    struct domain *dom;

	    dom = getdomain(addr->domain);

#if AUTH_PASSWD
	    pw = isvhost(dom) ? getvpwemail(dom, addr->user) : getpwnam(addr->user);
#else
	    pw = getvpwemail(dom, addr->user);
#endif
#if WITH_PAM
	    if ( !isvhost(dom) )
		ret = pam_login_ok("login", user, pass);
	    else
#endif
	    if (pw && pass && (encrypted = crypt(pass, pw->pw_passwd)) )
		ret = (strcmp(pw->pw_passwd, encrypted) == 0);
	}
	freeaddress(addr);
    }

    return ret;
}

/*
 * get a line from letter.in, handling the MaGiCaL * abort sequence.
 *
 * returns the decoded line or null; if null, *err contains:
 *          1 : !fgets
 *          2 : decode error
 *          3 : MaGiCaL *
 */
static char *
authgets(struct letter *let, int *errp)
{
    char line[520];
    char *ret;

    *errp = 1;
    if ( ret = fgets(line, sizeof line, let->in) ) {
	strtok(line, "\r\n");
	if (strcmp(line, "*") == 0) {
	    *errp = 3;
	    return 0;
	}
	if ( (ret = from64(line)) == 0)
	    *errp = 2;
    }
    return ret;
}


/*
 * authlogin() processes an AUTH LOGIN request
 */
static int
authlogin(struct letter *let, char *restofline)
{
    char *user, *pass;
    char *res;
    char auser[40];
    int err, ok = 0, code;

    auser[0] = 0;
    while (isspace(*restofline)) ++restofline;

    if (*restofline) 
	user = from64(restofline);
    else {
	message(let->out, 334, "<%s>", res=to64("Username:"));
	free(res);
	if ( (user = authgets(let, &err)) == 0 )
	    goto done;
    }
    strlcpy(auser,user, sizeof auser);

    message(let->out, 334, "<%s>", res=to64("Password:"));
    free(res);
    if ( (pass = authgets(let, &err)) == 0 ) {
	free(user);
	goto done;
    }
    ok = authmeharder(let, user, pass);
    err = ok ? 0 : 4;

    free(user);
    free(pass);

done:
    switch (err) {
    case 0:
	message(let->out, code=235, "Pass, friend!");
	break;
    case 2:
	message(let->out, code=501, "That's not a code I recognise!");
	break;
    case 3:
	message(let->out, code=501, "Okay.");
	break;
    case 4:
	message(let->out, code=535, "I do not recognise you.");
	break;
    default:
	message(let->out, code=421, "Hello?");
	break;
    }
    audit(let, "AUTH", auser, code);
    return ok;
}


/*
 * auth() handles AUTH <something>;  returns 1 if authentication
 * succeeded, 0 otherwise
 */
int
auth(struct letter *let, char *line)
{
    static didauth=0;
    int ret = 0;

    if (didauth) {
	audit(let, "AUTH", "", 503);
	message(let->out, 503, "Only one per customer, please!");
	return 0;
    }

    line += 4;	/* skip over "AUTH" */

    while (isspace(*line))
	++line;
    if (strncasecmp(line, "LOGIN", 5) == 0)
	ret = authlogin(let, line+5);
    else {
	audit(let, "AUTH", line, 504);
	message(let->out, 504, "Eh?");
    }

    if (ret)
	didauth=1;
    return ret;
}
