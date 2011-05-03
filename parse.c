#include "common.h"
#include "parse.h"
#include "cmd.h"


/* Last command */
static char last_cmd[MAX_SIZE] = "";


/* Common code */
/* Get address */
#define GET_ADDR()							\
	para = strtok(NULL, split);					\
	if (para && (*len >= sizeof(uint32_t))){			\
		*len = sizeof(uint32_t);				\
		if (-1 == (*(uint32_t*)buf = strtoul(para, NULL, 0))){	\
			/* Invalid address */				\
			printf("Invalid address.\n");			\
			return CMD_ERR;					\
		}							\
	} else {							\
		printf("Lack address.\n");				\
		return CMD_ERR;						\
	}


static int print_prefix()
{
	printf("dwd > ");
	return 0;
}

static int compare_cmd(char *str, char *cmd)
{
	char c;

	if (strncmp(str, cmd, strlen(cmd)) != 0)
		return -1;

	c = str[strlen(cmd)];
	if ((c >= 'A' && c <= 'Z')
	    || (c >= 'a' && c <= 'z'))
		return -1;

	return 0;
}

/* Parse parameters from commandline */
int parse_cmdl(int argc, char **argv, int *data)
{
	*data = (int)argv[0];

	if (argc < 2)
		return CMDL_USAGE;

	if (!compare_cmd(argv[1], "-h")
	    || !compare_cmd(argv[1], "--help"))
		return CMDL_HELP;
	else if (!compare_cmd(argv[1], "-a")
		 || !compare_cmd(argv[1], "--attach")) {
		pid_t pid;

		if (argc <= 2){
			printf("Lack pid of traced program.\n");
			return CMDL_ERR;
		}

		if ((pid = atoi(argv[2])) <= 0) {
			printf("Invalid pid.\n");
			return CMDL_ERR;
		}

		*data = pid;

		return CMDL_ATTACH;
	} else {
		*data = (int)&argv[1];
		return CMDL_DEBUG;
	}

	return CMDL_USAGE;
}

/* Parse user command */
int parse_cmd(uint8_t *buf, size_t *len)
{
	char cmd_buf[MAX_SIZE] = ""; /* For storing command */
	char split[8] = " ";	/* Split characters for parsing command */
	char *para;		/* Point to parameters in command */

	/* Initialize variables */
	print_prefix();
	fgets(cmd_buf, MAX_SIZE, stdin);

	/* Repeat? */
	if ('\n' == cmd_buf[0])
		/* Repeat last command */
		strcpy(cmd_buf, last_cmd);
	else
		/* Just store the command */
		strcpy(last_cmd, cmd_buf);


	/* Move the point to the command */
	para = strtok(cmd_buf, split);
	if (!para)
		return CMD_ERR;

	/* Help */
	if (!compare_cmd(para, "help"))
		return CMD_HELP;
	/* Continue */
	else if (!compare_cmd(para, "c")
		 || !compare_cmd(para, "continue"))
		return CMD_CONTINUE;

	/* Single step */
	else if (!compare_cmd(para, "s")
		 || !compare_cmd(para, "step"))
		return CMD_SINGLE_STEP;

	/* Quit */
	else if (!compare_cmd(para, "q")
		 || !compare_cmd(para, "quit"))
		return CMD_QUIT;

	/* Detach */
	else if (!compare_cmd(para, "detach"))
		return CMD_DETACH;

	/* Set breakpoint */
	else if (!compare_cmd(para, "b")
		 || !compare_cmd(para, "breakpoint")) {
		GET_ADDR();
		return CMD_BREAKPOINT;

		/* Disassembly */
	} else if (!compare_cmd(para, "disas")
		   || !compare_cmd(para, "disass")
		   || !compare_cmd(para, "disassembly")){
		GET_ADDR();
		return CMD_DISAS;

		/* Disassembly single instruction */
	} else if (!compare_cmd(para, "ds")
		   || !compare_cmd(para, "disas_s")
		   || !compare_cmd(para, "disas_single")
		   || !compare_cmd(para, "disassembly_single")){
		GET_ADDR();
		return CMD_DISAS_SINGLE;

		/* Peek memory or register */
	} else if (!compare_cmd(para, "x")
		   || !compare_cmd(para, "peek")){
		char *tmp;
		peek_t *peek;

		if (*len < sizeof(peek_t)) {
			printf("Memory is not enough\n");
			return CMD_ERR;
		}

		/* Initialize viables */
		peek = (peek_t *)buf;
		memset(peek, 0, sizeof(peek_t));

		/* Make tmp point to the first character after command */
		if ('x' == *para)
			tmp = para + 1;
		else
			tmp = para + strlen("peek"); /* para -> "peekABCD..."
						      *              ^
						      * tmp ---------| */

		/* para -> parameters */
		para = strtok(NULL, split);
		if (NULL == para) {
			printf("Lack parameters.\n");
			return CMD_ERR;
		}

		if ('/' == *tmp) {
			tmp++;
			if (isdigit(*tmp))
				peek->len = strtoul(tmp, NULL, 0);

			tmp = para - 1;
			while ((*tmp != '/') && !isalpha(*tmp))
				tmp--;

			if (*tmp != '/')
				peek->format = *tmp;
			else {
				printf("Incorrect format. See help.\n");
				return CMD_ERR;
			}
		} else
			peek->format = 'x';

		if ('$' == *para) {
			/* Rigster */
			strncpy(peek->reg, para,
				min(sizeof(peek->reg) - 1, strlen(para)));
			return CMD_PEEK_REG;
		} else {
			/* Memory */
			if (0 == (peek->addr = strtoul(para, NULL, 16))) {
				printf("Invalid address.\n");
				return CMD_ERR;
			}
			return CMD_PEEK_MEM;
		}

		return CMD_ERR;

		/* Poke, Change the value of memory or rigester */
	} else if (!compare_cmd(para, "poke")
		   || !compare_cmd(para, "poke")) {
		int user_cmd;
		poke_t *poke;

		if (*len < sizeof(peek_t)) {
			printf("Memory is not enough.\n");
			return CMD_ERR;
		}

		poke = (poke_t *)buf;
		memset(poke, 0, sizeof(poke_t));
		strcpy(split, " =");

		para = strtok(NULL, split);
		if (!para)
			return CMD_ERR;

		if (isdigit(*para)) {
			/* Memory */
			if (0 == (poke->addr = strtoul(para, NULL, 0))) {
				printf("Invalid address.\n");
				return CMD_ERR;
			}
			user_cmd = CMD_POKE_MEM;
		} else if ('$' == *para) {
			/* Rigester */
			strncpy(poke->reg, para, sizeof(poke->reg)-1);
			user_cmd = CMD_POKE_REG;
		} else {
			printf("Invalid parameters. See help.\n");
			return CMD_ERR;
		}

		/* Get value */
		para = strtok(NULL, split);
		if (!para) {
			printf("Lack value.\n");
			return CMD_ERR;
		}
		if (0 == (poke->value = strtoul(para, NULL, 0))) {
			printf("Invalid value.\n");
			return CMD_ERR;
		}

		return user_cmd;

		/* Set Shellcode */
	} else if (0 == compare_cmd(para, "shellcode")) {
		return CMD_SET_SHELLCODE;

		/* Inject shellcode */
	} else if (0 == compare_cmd(para, "inject")) {
		GET_ADDR();
		return CMD_INJECT_SHELLCODE;
	}

	return CMD_UNSUPPORTED;
}

