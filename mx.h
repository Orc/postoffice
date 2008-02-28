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


int getMXes(char*, int, struct iplist*);
int getIPa(char*, int, struct iplist*);
#define IP_NEW	0x01

void freeiplist(struct iplist*);

char *ptr(struct in_addr *addr);

#endif/*__MX_D*/
