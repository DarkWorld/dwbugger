#ifndef __CMD_H__
#define __CMD_H__ 1

#include "common.h"

/* For traced progress */
#define MAX_ARGS		31

/* Command */
#define CMD_ERR			-1
#define CMDL_ERR		-2

#define CMD_DISAS		0 /* Disassembly */
#define CMD_CONTINUE		1
#define CMD_SINGLE_STEP		2 /* Single step */
#define CMD_BREAKPOINT		3 /* Insert breakpoint */
#define CMD_QUIT		4 /* All is over */
#define CMD_PEEK_MEM		5 /* Peek memory */
#define CMD_PEEK_REG		6 /* Peek register */
#define CMD_POKE_MEM		7 /* Poke memory */
#define CMD_POKE_REG		8 /* Poke register */
#define CMD_DISAS_SINGLE	9 /* Disassebly-single instruction */
#define CMD_UNSUPPORTED		10
#define CMD_HELP		11
#define CMD_INJECT_SHELLCODE	12 /* Inject shellcode */
#define CMD_DETACH		13
#define CMD_ATTACH		14
#define CMD_SET_SHELLCODE 	15

/* Options got from commandline */
#define CMDL_ATTACH		100
#define CMDL_DEBUG		101
#define CMDL_USAGE		102 /* Print usage */
#define CMDL_HELP		103 /* Print help-info */

/* Error vaule handle_bp will return */
#define BP_ERR_NOT_EXIST	-1 /* Breakpoint is not exist */
#define BP_ERR_NOT_MATCH	-2 /* Addr is not match with eip */
#define BP_ERR_RESTORE_ORIG	-3 /* Failed to restore original vaule */

/* Breakpoint struct */
typedef struct
{
	uint32_t is_fresh;	/* does this breakpoint used? */
	uint32_t addr;		/* This breakpoint's address */
	uint32_t orig_data;
} bp_t;

/* Struct for peeking memory or rigester */
typedef struct
{
	char reg[11];
	char format;
	size_t len;
	uint32_t addr;
} peek_t;

/* Struct for altering memory or rigester */
typedef struct
{
	char reg[12];
	uint32_t addr;
	uint32_t value;
} poke_t;


/* Handle user's command */
int cmd(int user_cmd, uint8_t *data, size_t len);


#endif /* __CMD_H__ */

