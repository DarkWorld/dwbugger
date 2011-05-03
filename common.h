#ifndef __COMMON_H__
#define __COMMON_H__

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <stdint.h>

#include <ctype.h>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <sys/wait.h>

#include <sys/syscall.h>	/* For SYS_write etc */

#include <libgen.h>		/* For basename */


#define TRUE	1
#define FALSE	0

#define BUF_LEN		1024
#define MAX_SIZE	1024

#define min(x, y) ((x)>(y)? (y): (x))
#define max(x, y) ((x)<(y)? (y): (x))


/* Print error message and exit program */
int error(char *msg);


#endif
