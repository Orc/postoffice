/*
 * to64()   encode a string in base64
 * from64() decode a base64 string
 */
/*
 *		Copyright (C) 2004-2005 David Loren Parsons.
 *			All rights reserved.
 *
 *  Permission is hereby granted, free of charge, to any person
 *  obtaining a copy of this software and associated documentation files
 *  (the "Software"), to deal in the Software without restriction,
 *  including without limitation the rights to use, copy, modify, merge,
 *  publish, distribute, sublicence, and/or sell copies of the Software,
 *  and to permit persons to whom the Software is furnished to do so,
 *  subject to the following conditions:
 *
 *   1) Redistributions of source code must retain the above copyright
 *      notice, this list of conditions, and the following disclaimer.
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 *  IN NO EVENT SHALL DAVID LOREN PARSONS BE LIABLE FOR ANY DIRECT,
 *  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 *  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 *  OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <string.h>
#if __FreeBSD__
#  include <stdlib.h>
#else
#  include <malloc.h>
#endif

static char
table64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char
tablesci[] = {
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
	52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,-1, 0, 1, 2, 3, 4, 5, 6,
	 7, 8, 9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
	-1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,
	49,50,51,-1,-1,-1,-1,
};


char *
to64(char *clear)
{
    int sz;
    char *res, *out;

    if (clear == 0) return 0;
    sz = strlen(clear);

    if ( (res = malloc( ((sz*3)/2)+4 )) == 0) return 0;
    out = res;


    while (sz >= 3) {
	out[0] = table64[63 &  (clear[0] >> 2)                    ];
	out[1] = table64[63 & ((clear[0] << 4) | (clear[1] >> 4)) ];
	out[2] = table64[63 & ((clear[1] << 2) | (clear[2] >> 6)) ];
	out[3] = table64[63 &   clear[2]                          ];
	out += 4;
	clear += 3;
	sz -= 3;
    }
    if (sz) {
	out[0] = table64[63 &  (clear[0] >> 2)                    ];
	out[1] = table64[63 & ((clear[0] << 4) | (clear[1] >> 4)) ];
	out[2] = (sz == 2) ? table64[63 & (clear[1] << 2)] : '=';
	out[3] = '=';
	out += 4;
    }
    out[0] = 0;
    return res;
}


char *
from64(char *code)
{
    int sz;
    int cvt = 0;
    char *res, *out;
    unsigned char c[4];

    if (code == 0) return 0;
    sz = strlen(code);

    while ( (sz > 0) && isspace(code[sz-1]))
	--sz;

    if ( (res = malloc( ((sz*2)/3)+3) ) == 0) return 0;
    out = res;

    while (sz > 0 && code[0] != '=') {
	c[0] = tablesci[code[0]];
	c[1] = tablesci[code[1]];
	c[2] = tablesci[code[2]];
	c[3] = tablesci[code[3]];

	out[0] = (c[0]<<2) | (c[1]>>4);
	if (code[2] == '=') {
	    out[1] = 0;
	    return res;
	}
	out[1] = (c[1]<<4) | (c[2]>>2);

	if (code[3] == '=') {
	    out[2] = 0;
	    return res;
	}
	out[2] = (c[2]<<6) | (c[3]);

	code += 4;
	sz   -= 4;

	out += 3;
	cvt += 3;
    }
    out[0] = 0;
    return res;
}


#if DEBUG
main(argc, argv)
char **argv;
{
    int i;
    int decode = 0;
    char *res;

    if (argc > 1) {
	if (strcasecmp(argv[1], "decode") == 0) {
	    decode = 1;
	    ++argv, --argc;
	}
	else if (strcasecmp(argv[1], "encode") == 0) {
	    decode = 0;
	    ++argv, --argc;
	}
    }
    for (i=1; i < argc; i++) {
	if (decode) {
	    res=from64(argv[i]);
	    printf("[%s] -> [%s]\n", argv[i], res);
	}
	else {
	    res=to64(argv[i]);
	    printf("[%s] -> [%s]\n", argv[i], res);
	}
	free(res);
    }
}
#endif
