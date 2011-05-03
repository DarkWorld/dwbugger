#ifndef __DISAS_H__
#define __DISAS_H__ 1

#include <string.h>
#include <stdio.h>

#include "libdis.h"

#define PRINT_WIDTH	(7 * 3)	/* For print_insn */

#define INSN_RET	(0xC3)	/* RET */
#define INSN_HALT	(0xF4)	/* HALT */

#define INSN_MAX_LEN	16

#ifndef DISAS_SYNTAX
#define DISAS_SYNTAX	"att"
/* #define DISAS_SYNTAX	"intel" */
#endif

/* Disassembly a single instruction
 *
 * [IN]
 * raw_insn          : the raw data of the instruction
 * start_addr        : the instruction's address in program-memory
 * readable_insn_len : readable_insn's length
 *
 * [OUT]
 * readable_insn     : to store readable insn
 * insn_len          : the instruction's len(bytes) in raw data */
int disas_single_insn(uint8_t *raw_insn, uint32_t start_addr,
		      size_t readable_insn_len, char *readable_insn,
		      size_t *insn_len);


#endif /* __DISAS_H__ */

