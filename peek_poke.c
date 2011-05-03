#include "peek_poke.h"

/* Get values of memory */
int peek_mem(pid_t pid, uint32_t addr, uint8_t *buf, size_t *len)
{
	size_t peek_len;
	uint32_t word;

	peek_len = 0;

	while (peek_len < *len) {
		word = (int32_t)ptrace(PTRACE_PEEKDATA, pid,
				       addr + peek_len, NULL);
		if (-1 == word)
			break;

		if (peek_len < (*len & ~0x03))
			*(uint32_t *)(buf + peek_len) = word;
		else {
			int i;
			uint8_t *tmp = (uint8_t*)&word;

			for(i = 0; i < (*len & 0x03); i++)
				*(buf + peek_len + i) = *(tmp + i);

			peek_len += i;
			break;
		}

		peek_len += sizeof(uint32_t);
	}

	*len = peek_len;

	if (0 == peek_len)
		return -1;

	return 0;
}

/* Print values of registers */
int print_reg_value(pid_t pid, char *reg_name)
{
	struct user_regs_struct regs;

	if (-1 == ptrace(PTRACE_GETREGS, pid, NULL, &regs)) {
		perror("Get registers");
		return -1;
	}

	if (!strncmp(reg_name, "$regs", strlen("$regs"))
	    || !strncmp(reg_name, "$all", strlen("$all"))) {
                printf("eip: 0x%08lX\n"
		       "esp: 0x%08lX\n"
		       "ebp: 0x%08lX\n"
		       "eax: 0x%08lX\n"
		       "ebx: 0x%08lX\n"
		       "ecx: 0x%08lX\n"
		       "edx: 0x%08lX\n"
		       "esi: 0x%08lX\n"
		       "edi: 0x%08lX\n"
		       "xds: 0x%08lX\n"
		       "xes: 0x%08lX\n"
		       "xfs: 0x%08lX\n"
		       "xgs: 0x%08lX\n"
		       "xcs: 0x%08lX\n"
		       "xss: 0x%08lX\n"
		       "eflags: 0x%08lX\n"
		       "orig_eax: 0x%08lX\n",
		       regs.eip, regs.esp, regs.ebp, regs.eax, regs.ebx,
		       regs.ecx, regs.edx, regs.esi, regs.edi, regs.xds,
		       regs.xes, regs.xfs, regs.xgs, regs.xcs, regs.xss,
		       regs.eflags, regs.orig_eax);
	} else if (!strncmp(reg_name, "$eip", strlen("$eip")))
                printf("eip: 0x%08lX\n", regs.eip);
	else if (!strncmp(reg_name, "$esp", strlen("$esp")))
                printf("esp: 0x%08lX\n", regs.esp);
	else if (!strncmp(reg_name, "$ebp", strlen("$ebp")))
                printf("ebp: 0x%08lX\n", regs.ebp);
	else if (!strncmp(reg_name, "$eax", strlen("$eax")))
                printf("eax: 0x%08lX\n", regs.eax);
	else if (!strncmp(reg_name, "$ebx", strlen("$ebx")))
                printf("ebx: 0x%08lX\n", regs.ebx);
	else if (!strncmp(reg_name, "$ecx", strlen("$ecx")))
                printf("ecx: 0x%08lX\n", regs.ecx);
	else if (!strncmp(reg_name, "$edx", strlen("$edx")))
                printf("edx: 0x%08lX\n", regs.edx);
	else if (!strncmp(reg_name, "$esi", strlen("$esi")))
                printf("esi: 0x%08lX\n", regs.esi);
	else if (!strncmp(reg_name, "$edi", strlen("$edi")))
                printf("edi: 0x%08lX\n", regs.edi);
	else if (!strncmp(reg_name, "$xds", strlen("$xds")))
                printf("xds: 0x%08lX\n", regs.xds);
	else if (!strncmp(reg_name, "$xes", strlen("$xes")))
                printf("xes: 0x%08lX\n", regs.xes);
	else if (!strncmp(reg_name, "$xfs", strlen("$xfs")))
                printf("xfs: 0x%08lX\n", regs.xfs);
	else if (!strncmp(reg_name, "$xgs", strlen("$xgs")))
                printf("xgs: 0x%08lX\n", regs.xgs);
	else if (!strncmp(reg_name, "$xcs", strlen("$xcs")))
                printf("xcs: 0x%08lX\n", regs.xcs);
	else if (!strncmp(reg_name, "$xss", strlen("$xss")))
                printf("xss: 0x%08lX\n", regs.xss);
	else if (!strncmp(reg_name, "$eflags", strlen("$eflags")))
                printf("eflags: 0x%08lX\n", regs.eflags);
	else if (!strncmp(reg_name, "$orig_eax", strlen("$orig_eax")))
                printf("orig_eax: 0x%08lX\n", regs.orig_eax);
	else {
		printf("Incorrect register.\n");
		return -2;
	}

	return 0;
}

/* Alter values of memory */
int poke_mem(pid_t pid, uint32_t addr, uint8_t *buf, size_t len)
{
	size_t i;
	uint8_t tmp_buf[4];
	uint32_t word;

	i = 0;
	while (i < len){
		if (len - i >= 4)
			word = *(int*)(&buf[i]);
		else {
			memset(tmp_buf, 0, sizeof(tmp_buf));
			memcpy(tmp_buf, &buf[i], len - i);
			word = *(int*)tmp_buf;
		}

		if (ptrace(PTRACE_POKEDATA, pid, addr + i, word) == -1)
			return -1;
		i += 4;
	}

	return 0;
}

/* Alter values of register */
int poke_reg(pid_t pid, char *reg_name, uint32_t word)
{
	struct user_regs_struct regs;

	if (-1 == ptrace(PTRACE_GETREGS, pid, NULL, &regs))
		return -1;

	if (!strncmp(reg_name, "$eip", strlen("$eip")))
                regs.eip = word;
	else if (!strncmp(reg_name, "$esp", strlen("$esp")))
                regs.esp = word;
	else if (!strncmp(reg_name, "$ebp", strlen("$ebp")))
                regs.ebp = word;
	else if (!strncmp(reg_name, "$eax", strlen("$eax")))
                regs.eax = word;
	else if (!strncmp(reg_name, "$ebx", strlen("$ebx")))
                regs.ebx = word;
	else if (!strncmp(reg_name, "$ecx", strlen("$ecx")))
                regs.ecx = word;
	else if (!strncmp(reg_name, "$edx", strlen("$edx")))
                regs.edx = word;
	else if (!strncmp(reg_name, "$esi", strlen("$esi")))
                regs.esi = word;
	else if (!strncmp(reg_name, "$edi", strlen("$edi")))
                regs.edi = word;
	else if (!strncmp(reg_name, "$xds", strlen("$xds")))
                regs.xds = word;
	else if (!strncmp(reg_name, "$xes", strlen("$xes")))
                regs.xes = word;
	else if (!strncmp(reg_name, "$xfs", strlen("$xfs")))
                regs.xfs = word;
	else if (!strncmp(reg_name, "$xgs", strlen("$xgs")))
                regs.xgs = word;
	else if (!strncmp(reg_name, "$xcs", strlen("$xcs")))
                regs.xcs = word;
	else if (!strncmp(reg_name, "$xss", strlen("$xss")))
                regs.xss = word;
	else if (!strncmp(reg_name, "$eflags", strlen("$eflags")))
                regs.eflags = word;
	else if (!strncmp(reg_name, "$orig_eax", strlen("$orig_eax")))
                regs.orig_eax = word;
	else
		return -2;

	if (-1 == ptrace(PTRACE_SETREGS, pid, NULL, &regs))
		return -3;

	return 0;
}
