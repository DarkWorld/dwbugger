#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <stdint.h>

#include <ctype.h>

#include <unistd.h>
#include <time.h>
#include <sys/time.h>

#include <sys/types.h>
#include <sys/wait.h>

#include <sys/user.h>
#include <sys/reg.h>			/* For constants ORIG_EAX etc*/
#include <sys/syscall.h>		/* For SYS_write etc */


#define TRUE	1
#define FALSE	0


#define min(x, y) ((x)>(y)? (y): (x))
#define max(x, y) ((x)<(y)? (y): (x))


typedef struct 
{
    char reg[11];
    char format;
    int len;
    uint32_t addr;
} peek_t;

typedef struct 
{
    char reg[12];
    uint32_t addr;
    uint32_t value;
} poke_t;


#endif
