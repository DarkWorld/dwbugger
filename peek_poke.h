#ifndef __PEEK_POKE_H__
#define __PEEK_POKE_H__ 1

#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <sys/types.h>		/* For pid_t? */
#include <sys/ptrace.h>
#include <sys/user.h>

/* 0: success, < 0: failure */
int peek_mem(pid_t pid, uint32_t addr, uint8_t *buf, size_t *len);
int print_reg_value(pid_t pid, char *reg_name); /* -1: Failed to get regs
						 * -2: Incorrect reg name */
int poke_mem(pid_t pid, uint32_t addr, uint8_t *buf, size_t len);
int poke_reg(pid_t pid, char *reg, uint32_t word); /* -1: Failed to get regs
						    * -2: Incorrect reg name
						    * -3: Failed to alter */


#endif

