#include "disas.h"

/* Generate readable instruction-string */
static int gen_readable_insn_str(x86_insn_t *insn, char *readable_insn,
				 size_t readable_insn_len)
{
	int i;
	size_t len;
	char *ptr;
	int syntax;

	syntax = !strcmp(DISAS_SYNTAX, "att")? att_syntax: intel_syntax;

	ptr = readable_insn;
	memset(readable_insn, 0, readable_insn_len);

	snprintf(ptr, readable_insn_len - 1, "0x%08x:\t", insn->addr);
	ptr += strlen(ptr);

	len = ptr - readable_insn;
	if (len > 0 && readable_insn_len - len - 1 == 0
	    && readable_insn_len - len - 1 < PRINT_WIDTH * 2)
		return -1;

	i = 0;
	while (i < PRINT_WIDTH / 3) {
		/* 3 width */
		if (i < insn->size) {
			sprintf(ptr, "%02x ", insn->bytes[i]);
		} else
			sprintf(ptr, "   ");
		i++;
		ptr += strlen(ptr);
	}

	sprintf(ptr, "\t");
	ptr += strlen(ptr);

	len = ptr - readable_insn;

	if (len > 0 && readable_insn_len - len - 1 < 4)
		return -1;

	x86_format_insn(insn, ptr, readable_insn_len - len - 1, syntax);

	return 0;
}

/* Disassebly a single instruction */
int disas_single_insn(uint8_t *raw_insn, uint32_t start_addr,
		      size_t readable_insn_len, char *readable_insn,
		      size_t *insn_len)
{
	x86_insn_t insn;

	x86_init(opt_none, NULL, NULL);
	*insn_len = x86_disasm(raw_insn, INSN_MAX_LEN, 0, 0, &insn);
	if (*insn_len) {
		insn.addr = start_addr;
		insn.offset = 0;
		gen_readable_insn_str(&insn, readable_insn, readable_insn_len);
	} else
		return -1;

	x86_cleanup();

	return 0;
}

