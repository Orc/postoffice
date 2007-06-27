#ifndef __MX_D
#define __MX_D

#include <sys/socket.h>
#include <netinet/in.h>

struct ipa {
    short key;
    struct in_addr addr;
} ;

struct iplist {
    int size, count;
    struct ipa *a;
} ;


int getMXes(char*, struct iplist*);
void freeiplist(struct iplist*);

char *ptr(unsigned long*);

#endif/*__MX_D*/
