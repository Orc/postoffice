#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <string.h>

#if HAVE_MALLOC_H
#   include <malloc.h>
#endif

#include "mymalloc.h"

#if __linux__
#   include <linux/if.h>
#endif

struct in_addr *
local_if_list()
{
    static struct in_addr localhost[2];
#if __linux__
    struct in_addr *res = 0;
    int szres = 0,
	maxres= 0;

    char bfr[1024];
    int left;
    int eth = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifconf ask;
    struct ifreq *dev;
    struct in_addr ip;

    ask.ifc_buf = bfr;
    ask.ifc_len = sizeof bfr;

    if (ioctl(eth, SIOCGIFCONF, &ask) != -1) {
	dev = (struct ifreq*) ask.ifc_req;
	left = ask.ifc_len / sizeof *dev;

	for (; left-- > 0; dev++) {
	    struct ifreq cur;

	    strcpy(cur.ifr_name, dev->ifr_name);

	    if (ioctl(eth, SIOCGIFADDR, &cur) == -1)
		continue;

	    if (strcmp(dev->ifr_name, "lo") == 0) {
		unsigned int *p = (unsigned int*) &(dev->ifr_addr);

		ip = *(struct in_addr*)(p+1);
	    }
	    else if (cur.ifr_addr.sa_family == AF_INET) { 
		struct sockaddr_in *p = (struct sockaddr_in*)&cur.ifr_addr;

		ip = p->sin_addr;
	    }
	    else
		continue;

	    if ( (szres + 2) >= maxres ) {
		maxres += 10;
		res = res ? realloc(res, maxres*sizeof(ip))
			  : malloc(maxres*sizeof(ip));
	    }
	    if (res == 0)
		break;

	    res[szres++] = ip;
	}
    }
    close(eth);

    if (res) {
	res[szres].s_addr = 0;
	return res;
    }

#elif USE_IFCONFIG
    struct in_addr *res = 0;
    char bfr[1024];
    char *p;
    in_addr_t ipa;
    struct in_addr ip;
    FILE *f;
    int szres = 0;
    int maxres = 0;


    if ( (f = popen("/sbin/ifconfig -a inet 2>/dev/null", "r")) ) {
	while (fgets(bfr, sizeof bfr, f))
	    if ( (p = strstr(bfr, "inet "))
	      && ((ipa = inet_addr(p+5)) != INADDR_NONE)) {
		if ( (szres + 2) >= maxres ) {
		    maxres += 10;
		    res = res ? realloc(res, maxres*sizeof(ip))
			      : malloc(maxres*sizeof(ip));
		}
		if (res == 0)
		    break;

		res[szres++] = inet_makeaddr(ntohl(ipa), 0L);
	    }
	pclose(f);
	if (res) {
	    res[szres].s_addr = 0;
	    return res;
	}
    }

#endif
    /* hand-build an interfaces list that only contains localhost
     */
    localhost[1].s_addr = 0;
    localhost[0] = inet_makeaddr(ntohl(inet_addr("127.0.0.1")), 0L);

    return localhost;
}


#ifdef DEBUG
main()
{
    struct in_addr *ip = local_if_list();

    for (; ip->s_addr; ip++)
	puts(inet_ntoa(*ip));
}
#endif
