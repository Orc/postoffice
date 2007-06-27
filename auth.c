#include "config.h"
#include "letter.h"

#include <stdio.h>
#include <ndbm.h>


#if WITH_AUTH

static int
authchat(struct letter *let, char *prompt, char *bfr, int len)
{
    int len;

    message(let, 334, prompt);
    if (fgets(bfr, len, let->in) == 0) {
	audit(letter, "AUTH","EOF",499);
	byebye(let, 1);
    }
    len = strlen(bfr);

    if (len > 1 && bfr[len-1] == '\n' && bfr[len-2] == '\r')
	bfr[len-2] = 0;
    else if (len > 0 && bfr[len-1] == '\n')
	bfr[len-1] = 0;

    else if ( (bfr[0] == '*') && (bfr[1] == 0) ) {
	message(let, 501, "Abort! Abort! OK!");
	return 501;
    }
    return 235;
}

int
authlogin(struct letter *let)
{
    char user[200];
    char pass[80];
    int code;
    datum key, value;
    DB *authdb;
    int good = 0;

    if ( (code = authchat(let, "VXNlcm5hbWU6", user, sizeof user)) != 235 )
	audit(let, "AUTH", "Username: *", code);
    else if ( (code = authchat(let, "UGFzc3dvcmQ6", pass, sizeof pass)) != 235 )
	audit(let, "AUTH", "Password: *", code);
    else if (authdb = dbm_open(AUTHDB, O_RDONLY, 0)) {
	key.dptr = user;
	key.dsize = strlen(user)+1;

	value = dbm_fetch(key);

	if (value.dptr && strncmp(value.dptr, pass, value.dsize) == 0)
	    good = 1;

	dbm_close(AUTHDB);
	audit(let, "AUTH", user, code = (good ? 235 : 501));

	message(let, code, "Barney %s you!", good ? "loves" : "hates");
    }
    return good;
}

#endif
