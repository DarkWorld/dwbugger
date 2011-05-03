#include "common.h"

int error(char *msg)
{
	perror(msg);
	exit(-1);
}
