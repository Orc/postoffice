#include <stdio.h>  
#include <security/pam_appl.h>  
#include <unistd.h>  
#include <stdlib.h>  
#include <string.h>  
#include <syslog.h>
#include "config.h"


/* don't prompt for a password, just give a pre-filled one
 */
static int
dont_ask(int num_msg,
	 const struct pam_message **msg,
	 struct pam_response **resp,
	 void *appdata_ptr)  
{  
    *resp = appdata_ptr;  
    return PAM_SUCCESS;  
}  


/* complain about a pam failure, using pam_strerror() if available
 */
static void
pam_log(pam_handle_t *magic, char *message, int code)
{
#if HAVE_PAM_STRERROR
    syslog(LOG_DEBUG, "%s (%s)", message, pam_strerror(magic, code));
#else
    syslog(LOG_DEBUG, "%s (code %d)", message, code);
#endif
}


/* authorise via pam.  Might work, might not work, it's all a mystery
 */
int
pam_login_ok(char *service, char *user, char *password)   
{  
    struct pam_response *reply = malloc(sizeof *reply);
    struct pam_conv pretend_to_talk = { dont_ask, reply };
    pam_handle_t *auth = NULL;
    int status, is_ok = 0;  

    
    if ( reply ) {
	reply->resp = strdup(password);
	reply->resp_retcode = 0;
    }
    else {
	/*syslog(LOG_ERR, "pam_login_ok: cannot allocate %ld bytes", (long)sizeof *reply);*/
	return 0;
    }
    
    status = pam_start(service, user, &pretend_to_talk, &auth);

    if ( status != PAM_SUCCESS ) {
	/*pam_log(auth, "pam_start failed", status);*/
	free(reply->resp);
	free(reply);
    }
    else {
	switch ( status = pam_authenticate(auth, 0) ) {
	case PAM_SUCCESS:   is_ok = 1;
			    break;
	case PAM_SYMBOL_ERR:
	case PAM_SERVICE_ERR:
	case PAM_SYSTEM_ERR:
	case PAM_BUF_ERR:
	case PAM_OPEN_ERR:  /*pam_log(auth, "pam_auth failed", status);*/
	default:            /*permission denied for normal reasons; no logging needed*/
			    is_ok = 0;
			    break;
	}
    }

    pam_end(auth,status);
    return is_ok;  
}  


#ifdef TEST
main(int argc, char** argv)  
{  
    if (argc != 3) {  
	fprintf(stderr, "usage: %s username password\n", argv[0]);
	return 1;  
    }  

    if ( pam_login_ok("passwd", argv[1], argv[2]) ) {  
	puts("Yes");
	return 0;  
    }     

    puts("No");
    return 1;  
}  
#endif
