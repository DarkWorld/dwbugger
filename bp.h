#ifndef __BP_H__
#define __BP_H__

#include "common.h"

/* Breakpoint struct */
typedef struct
{
	uint32_t is_fresh;	/* Have the breakpoint been used */
	uint32_t addr;		/* This breakpoint's address */
	uint32_t orig_data;	/* The content of the breakpoint-address */
}bp_t;

#endif /* __BP_H__ */

