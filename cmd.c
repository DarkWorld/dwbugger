#include "common.h"
#include "cmd.h"
#include "parse.h"
#include "disas.h"
#include "peek_poke.h"

static pid_t s_tpid;		/* ID of traced process */
static bp_t s_bp;		/* Breakpoint */
static char s_shellcode[MAX_SIZE] = 	/* Standard Shellcode */
	"\x31\xc0\x31\xdb\xb0\x17\xcd\x80\xeb\x1f\x5e\x89\x76\x08\x31"
	"\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d"
	"\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff"
	"\xff\x2f\x62\x69\x6e\x2f\x73\x68";


/* Quit */
static int quit()
{
	/* Kill child process and quit */
	kill(s_tpid, SIGTERM);
	exit(0);
}

/* Disassembly single struction */
static int disas_single(uint32_t addr)
{
	size_t raw_data_len;
	size_t insn_len;
	uint8_t raw_data[64] = "\x00";
	char printable_insn[64] = "\x00";

	/* Disassembly */
	raw_data_len = sizeof(raw_data);
	peek_mem(s_tpid, addr, raw_data, &raw_data_len);

	disas_single_insn(raw_data, addr, sizeof(printable_insn),
			  printable_insn, &insn_len);

	/* Print it */
	printf("%s\n", printable_insn);
	fflush(stdout);

	return 0;
}

/* Disassembly structions */
static int disas(uint32_t addr)
{
	uint8_t raw_data[MAX_SIZE] = "\xc3";
	char print_insn_buf[128] = "\x00";
	char is_continue[8] = "\x00";
	size_t raw_data_len;	/* Len for raw_data */
	size_t insn_len;	/* Size of instruction */

	int stop_flag;
	int insn_num;
	int cur_pos;
	uint32_t start_addr;

	start_addr = addr;
	stop_flag = TRUE;

	while (TRUE == stop_flag) {
		/* Get raw data of instruction from addr */
		raw_data_len = MAX_SIZE;
		if (peek_mem(s_tpid, start_addr, raw_data,
			     &raw_data_len) < 0) {
			printf("Failed to read values of the memory(%#x)\n",
			       start_addr);
			return -1;
		}

		cur_pos = 0;
		insn_num = 0;
		while (insn_num < 50 && cur_pos < raw_data_len) {
			/* Parse these instructions */
			if (disas_single_insn(&raw_data[cur_pos],
					      start_addr + cur_pos,
					      sizeof(print_insn_buf),
					      print_insn_buf,
					      &insn_len) < 0){
				cur_pos++;
				printf("Invalid instruction.\n");
				continue;
			}

			/* print instruction */
			printf("%s\n", print_insn_buf);
			fflush(stdout);

			if (1 == insn_len) {
				if (INSN_RET == raw_data[cur_pos]) {
					/* RET */
					/* Stop loop !!! */
					stop_flag = FALSE;
					break;
				} else if (INSN_HALT == raw_data[cur_pos]) {
					/* HALT */
					printf("[!!!!!!] Haha :D ===== "
					       "Halt has been captured. ");
					break;
				}
			}

			cur_pos += insn_len;
			insn_num++;
		}

		if (stop_flag != TRUE)
			break;

		printf("[!!!!!!] Go on?([Yy]/[Nn]) : ");
		fgets(is_continue, sizeof(is_continue - 1), stdin);

		if (('y' == is_continue[0]) ||('Y' == is_continue[0])) {
			/* Continue to disassembly */
			start_addr += cur_pos;
		} else
			break;
	}

	return 0;
}

/* Insert breakpoint */
static int insert_bp(uint32_t addr)
{
	int tmp;

	/* Restore original data */
	if (TRUE == s_bp.is_fresh) {
		tmp = ptrace(PTRACE_POKEDATA, s_tpid, s_bp.addr,
			     s_bp.orig_data);
		if (-1 == tmp)
			return -1;
	}

	/* Initialize bp */
	memset(&s_bp, 0, sizeof(bp_t));

	tmp = ptrace(PTRACE_PEEKDATA, s_tpid, addr, NULL);
	if (-1 == tmp)
		return -1;

	/* Store original data */
	s_bp.orig_data = tmp;

	/* int 3 */
	if (ptrace(PTRACE_POKEDATA, s_tpid, addr, (tmp & ~0xFF) | 0xCC) == -1)
		return -1;

	s_bp.is_fresh = TRUE;
	s_bp.addr = addr;

	return 0;
}

/* Handle breakpoint when facing breakpoint */
static int handle_bp()
{
	struct user_regs_struct reg;

	if (s_bp.is_fresh != TRUE)
		return BP_ERR_NOT_EXIST;

	ptrace(PTRACE_GETREGS, s_tpid, NULL, &reg);
	if (s_bp.addr != reg.eip - 1)   /* They're not matched. */
		return BP_ERR_NOT_MATCH;

	printf("Stopped by breatpoint 0x%08X\n", s_bp.addr);
	/* Restore original value */
	reg.eip = s_bp.addr;
	if ((ptrace(PTRACE_SETREGS, s_tpid, NULL, &reg) == -1)
	   || (ptrace(PTRACE_POKEDATA, s_tpid, s_bp.addr,
		      s_bp.orig_data) == -1)) {
		printf("Failed to restore original data in "
		       "breakpoint 0x%08X\n",
		       s_bp.addr);

		return BP_ERR_RESTORE_ORIG;
	}

	/* This breakpoint has been used now */
	s_bp.is_fresh = FALSE;

	return 0;
}

/* Continue */
static int cont()
{
	int status;

	ptrace(PTRACE_CONT, s_tpid, 0, 0);
	wait(&status);
	if (WIFEXITED(status)) {
                printf("\nTraced process exited!\n");
		exit(0);
	} else if (WIFSTOPPED(status)) {
                switch (handle_bp()) {
                case BP_ERR_NOT_EXIST:
                case BP_ERR_NOT_MATCH:
			/* Continue to run */
			cont();
			break;
                case BP_ERR_RESTORE_ORIG:
			break;
                default:
			disas_single(s_bp.addr);
			break;
                }
	}

	return 0;
}

/* Single-step */
static int step()
{
	int status;
	struct user_regs_struct regs;

	ptrace(PTRACE_SINGLESTEP, s_tpid, 0, 0);
	wait(&status);

	ptrace(PTRACE_GETREGS, s_tpid, NULL, &regs);
	disas_single(regs.eip);

	return 0;
}

static int peek(peek_t peek)
{
	size_t len;
	size_t print_len;
	uint8_t buf[MAX_SIZE + 1];

	/* Peek register */
	if (strlen(peek.reg) > 0) {
		print_reg_value(s_tpid, peek.reg);
		return 0;
	}

	/* Peek memory */
	len = max(peek.len, 1);
	if ('x' == peek.format)
                len *= 4;
	else if ('s' == peek.format)
                len = MAX_SIZE;
	len = min(len, MAX_SIZE);

	if (peek_mem(s_tpid, peek.addr, buf, &len) < 0) {
                printf("Failed to read memory(0x%08X)\n",
		       peek.addr);
                return -1;
	}

	if ('s' == peek.format) {
                printf("%s\n", buf);
                return 0;
	}

	if (peek.format != 'b' && peek.format != 'x' && peek.format != 0) {
                printf("Unsupported format\n");
                return 0;
	}

	/* Print the data according to the FORMAT  */
	print_len = 0;
	while (print_len < len) {
                if (print_len % 16 == 0)
			printf("0x%08x:\t", peek.addr + print_len);

                if ('b' == peek.format) {
			printf(" %02x", *(buf + print_len));
			print_len++;
                } else {
			printf(" %08x", *(uint32_t*)(buf + print_len));
			print_len += 4;
                }

                if (print_len % 16 == 0) {
			printf("\n");
			continue;
                }

                if (print_len % 8 == 0)
			printf(" ");
	}
	if (print_len % 16 != 0)
                printf("\n");

	return 0;
}

static int poke(poke_t poke)
{
	if (strlen(poke.reg) > 0) {
		if (poke_reg(s_tpid, poke.reg, poke.value) < 0 )
			printf("Failed to alter value of %s", poke.reg);
		return 0;
	}

	if (poke_mem(s_tpid, poke.addr, (uint8_t*)&(poke.value),
		     sizeof(int)) < 0)
                printf("Failed to alter value of the memory(0x%08X)",
		       poke.addr);

	return 0;
}

/* Alter g_shellcode's value */
static int set_shellcode()
{

	return 0;
}

/* Inject shellcode into some address */
static int inject_shellcode(uint32_t addr)
{
	int shellcode_len;
	struct user_regs_struct regs;

	shellcode_len = strlen(s_shellcode);
	if(shellcode_len <= 0) {
                printf("Please set shellcode first. See help.\n");
                return -1;
	}

	if(0 == addr) {
                ptrace(PTRACE_GETREGS, s_tpid, NULL, &regs);
                addr = (uint32_t)regs.esp - 1024;
	}

	if(-1 == poke_mem(s_tpid, addr, (uint8_t*)s_shellcode,
			  shellcode_len)) {
                printf("Failed to inject shellcode.\n");
                return -1;
	}

	printf("Suceed to inject shellcode to %#x.\n", addr);

	return 0;
}

int detach()
{
	if(-1 == ptrace(PTRACE_DETACH, s_tpid, 0, 0))
                perror("detach");

	printf("Succeed to detach.\n");
	return 0;
}

/* Print usage info */
static int print_usage(char *prog_name)
{
	printf("Usage:\n"
	       "\t%s <program> [arguments]\n"
	       "\t%s -a/--attach <pid>\n"
	       "\t%s -h/--help\n",
	       prog_name, prog_name, prog_name);

	return 0;
}

/* Print help info about commands in dwbugger */
static int print_help()
{
	char buf[] =
		"Commands list in dwd:\n"
		"s/ step:\n"
		"\tForward a single step.\n"
		"c/ continue:\n"
		"\tContinue to run the process.\n"
		"q/ quit:\n"
		"\tQuit.\n"
		"b/ bp/ breakpoint <address>:\n"
		"\tSet a breakpoint.\n"
		"ds <address>:\n"
		"\tJust disassembly only one instruction.\n"
		"disas/ disass/ disassembly <address>:\n"
		"\tDisassembly codes.\n"
		"x/[len][format flag] <memory-address/register>:\n"
		"\tShow the value of memory or register.\n"
		"\tFormat flag can be 'x'(4 bytes) , 'b'(1 byte), "
		"or 's'(string). \n"
		"\tAnd register can be '$all', "
		"'$regs'(display all the registers), \n"
		"\t'$eip', '$esp', '$ebp', '$eax', '$ebx', '$ecx', '$edx', "
		"'$esi', \n"
		"\t'$edi', '$xds', '$xes', '$xfs', '$xgs', '$xcs', '$xss',"
		"'$eflags', \n"
		"\t'$orig_eax'.\n"
		"set <memory-address/register>=<value>:\n"
		"\tAlter the value of memory or register. \n"
		"\tAnd register can be '$eip', '$esp', '$ebp', '$eax', "
		"'$ebx',\n"
		"\t'$ecx', '$edx', '$esi', '$edi', '$xds', '$xes', '$xfs',\n"
		"\t'$xgs', '$xcs', '$xss', '$eflags', '$orig_eax'.\n";

	printf("%s", buf);

	return 0;
}

/* Print help info for '-h/--help' options */
static int print_cmdl_help(char *prog_name)
{
	printf("DarkWorld's debugger (dwbugger).\n"
	       "License GPLv2.\n\n"
	       "Debug or trace program: %s <program> [arguments]\n"
	       "Attach to some program: %s --attach <pid>\n",
	       prog_name, prog_name);

	printf("\nCommands in %s:\n", prog_name);
	print_help();

	printf("\nEnjoy it.\n");

	return 0;
}

/* Get address of main function */
static int get_main_addr()
{

	return 0;
}

/* Move eip to main function */
static int eip_to_main()
{
	uint32_t addr;

	/* Get main fuction's address */
	addr = get_main_addr();
	if (-1 == addr)
		return -1;

	/* Inject breakpoint in that address */
	if (insert_bp(addr) < 0)
		return -1;

	/* Run */
	cont();

	return 0;
}

/* Initialize */
static int init_trace()
{
	int status;
	int tmp;
	struct user_regs_struct regs;

	/* Initialize global variables */
	s_bp.is_fresh = FALSE;

	/* Wait traced process */
	wait(&status);

	/* Move eip to main function */
	tmp = eip_to_main();

	/* Print initial information */
	ptrace(PTRACE_GETREGS, s_tpid, NULL, &regs);
	printf("pid: %d\n"
	       "eip: 0x%08lx\n"
	       "esp: 0x%08lx\n"
	       "ebp: 0x%08lx\n",
	       s_tpid, regs.eip, regs.esp, regs.ebp);

	if (!tmp)
		printf("Stopping in main function, good luck.\n");

	return 0;
}

/* Attack some process */
static int attach(pid_t pid)
{
	s_tpid = pid;
	if (ptrace(PTRACE_ATTACH, s_tpid, 0, 0) < 0)
		error("Attach");

	init_trace();

	return 0;
}

/* Start to debug */
static int debug(char **argv)
{
	int i;
	char *args_array[MAX_ARGS + 1] = {NULL};

	s_tpid = fork();
	if (s_tpid < 0)
		error("Fork");

	/* This is parent process */
	if (s_tpid > 0) {
		init_trace();
		return 0;
	}

	/* This is the child process */
	/* Prepare arguments for the program and
	 * Excute it */
	for(i = 0; i < MAX_ARGS && argv[i] != NULL; i++)
		args_array[i] = argv[i];
	args_array[i] = NULL;

	/* Wait to be traced */
	ptrace(PTRACE_TRACEME, 0, 0, 0);

	execv(argv[0], args_array);

	/* Error happens,
	 * Tell parent prcess to quit */
	perror("Execl");
	kill(getppid(), SIGTERM);
        exit(-1);
}

/* Core function */
/* Dispatch user command to related function */
int cmd(int user_cmd, uint8_t *data, size_t len)
{
	switch (user_cmd) {
	case CMDL_ERR:
		exit(-1);
	case CMDL_USAGE:
		print_usage(basename((char *)data));
		exit(-1);
	case CMDL_HELP:
		print_cmdl_help(basename((char *)data));
		exit(-1);
	case CMDL_ATTACH:
		attach((pid_t)data);
		break;
	case CMDL_DEBUG:
		debug((char**)data);
		break;

	case CMD_ERR:
		break;
	case CMD_HELP:
		print_help();
		break;
	case CMD_QUIT:
		quit();
		break;
	case CMD_DISAS:
		disas(*(uint32_t*)data);
		break;
	case CMD_DISAS_SINGLE:
		disas_single(*(uint32_t*)data);
		break;
	case CMD_CONTINUE:
		cont();
		break;
	case CMD_SINGLE_STEP:
		step();
		break;
	case CMD_BREAKPOINT:
		printf("%s to insert breakpoint on 0x%08X.\n",
		       insert_bp(*((uint32_t*)data))? "Failed ": "Succeed ",
		       *((uint32_t*)data));
		break;
	case CMD_PEEK_MEM:
	case CMD_PEEK_REG:
		peek(*(peek_t*)data);
		break;
	case CMD_POKE_MEM:
	case CMD_POKE_REG:
		poke(*(poke_t*)data);
		break;
	case CMD_DETACH:
		detach();
		break;

/* !!!WARNING!!! */
/* The following two commands are not efficient.
 * So they are not introduced in help-info. */
	case CMD_SET_SHELLCODE:
		set_shellcode();
		break;
	case CMD_INJECT_SHELLCODE:
		inject_shellcode(*(uint32_t*)data);
		break;

	default:
		printf("Invalid command. See help.\n");
		break;
	}

	return 0;
}
