#include <stdio.h>  
#include <security/pam_appl.h>  
#include <unistd.h>  
#include <stdlib.h>  
#include <string.h>  
#include <syslog.h>


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


/* authorise via pam.  Might work, might not work, it's all a mystery
 */
int
pam_login_ok(char *service, char *user, char *password)   
{  
    struct pam_response *reply = malloc(sizeof(*reply));
    struct pam_conv pretend_to_talk = { dont_ask, reply };
    pam_handle_t *auth = NULL;
    int status;  

    
    if ( reply ) {
	reply->resp = strdup(password);  
	reply->resp_retcode = 0;  
    }
    else {
	syslog(LOG_ERR, "pam_login_ok: cannot malloc(%d)", sizeof(*reply));
	return 0;
    }
    
    status = pam_start(service, user, &pretend_to_talk, &auth);

    if ( status != PAM_SUCCESS ) {
	syslog(LOG_ERR, "pam_start failed (code %d)", status);
	return 0;
    }

    if ( (status = pam_authenticate(auth, 0)) != PAM_SUCCESS) {
	switch (status) {
	default:          syslog(LOG_ERR, "pam_auth failed (code %d)", status);
	case PAM_AUTH_ERR:return 0;
	}
    }

    pam_end(auth,status);
    return 1;  
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
