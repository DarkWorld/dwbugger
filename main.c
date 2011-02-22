/*
 *
 * 
 * LICENSE: GPLv2 (its link: http://www.gnu.org/licenses/gpl-2.0.html)
 * or you can view file ./license.txt
 *
 *
 * 
 *
 *
 * 
 * DarkWorld's debugger
 *
 *
 *
 *
 * Discription:
 *     It's a lightweight dynamic debugger in assembly-language level.
 *     All of it's dubug-function is implemented via ptrace. So it
 *     doesn't need read permission.
 *
 *     It can inset breakpoint, peek values of memory or registers,
 *     alter values of memory or registers, continue, step by
 *     step etc.
 *
 *     Enjoy it.
 *
 *
 *
 * 
 * Advantage:
 *     Needs no read permission. 
 * Disadvantage:
 *     Only has basic functions. has It doesn't offer any information
 *     of symbols.
 *
 *
 *
 *
 *
 * Command:
 * help - print help information
 * disass/disassembly <address> - disassembly address's machine code
 * peek/[len][format flag] <memory address or register>
 * poke <memory address or register>=<value>
 *
 * 
 */

#include "common.h"
#include "portable_ptrace.h"
#include "libdis.h"
#include "bp.h"


static bp_t g_bp;


/* Print prefix "dWbugger > " before we input cmd */
int print_prefix ();
int print_help ();
int disass (pid_t cpid, uint32_t addr); /* Disassembly from addr to "RET" */
int disass_single (pid_t cpid, uint32_t addr); /* Single instruction */
int parse_cmd (uint8_t *buf, int *len);   /* Parse input command */
/* Peek memory */
int peek_m (pid_t pid, uint32_t addr, uint8_t *buf, int *len);
/* Peek register */
int peek_r (pid_t pid, uint32_t addr, uint8_t *buf, int *len);
int debug (pid_t cpid);
int insert_bp (pid_t cpid, uint32_t addr, bp_t *); /* Insert breakpoint */
int handle_bp (pid_t cpid, bp_t); /* Handle breakpoint */


int main (int argc, char **argv)
{
 	pid_t pid;

    if (argc < 2) {
        printf ("\nUsage: %s <path of the traced program> "
				"[arguments for traced program]\n\n"
                "If this is the first time to use this program, pls read "
				"README first.\nOr you can type '%s -h' or '%s --help' to get"
				" some help info.\n\nEnjoy it!\n\n",
				argv[0], argv[0], argv[0]);
        exit (0);
    }

    if (!strncmp (argv[1], "-h", strlen ("-h"))
        || !strncmp (argv[1], "--help", strlen ("-h"))) {
        print_help ();
        exit (0);
    }
    
    /* Fork */
    switch ((pid = fork ()) < 0) {
        printf ("fork err");
        exit (1);
    }

    /* Child process; Ready for staced */
    if (0 == pid) {

#define MAX_ARGS	31

		int i;
		char *args_array[MAX_ARGS + 1] = {NULL};

		for (i = 0; i < MAX_ARGS && i < argc - 1; i++) {
			args_array[i] = argv[i + 1];
		}

		args_array[i] = NULL;

        ptrace (PTRACE_TRACEME, 0, 0, 0);
		
		execv (argv[1], args_array);
        
        printf ("execl err\n");
        kill (getppid (), SIGKILL);
        exit (1);
    }

    printf ("DarkWorld's debugger. http://\n");

    /* Start to debug */
    debug(pid);

    return 0;
}

int debug (pid_t cpid)
{
 
#define BUF_LEN		1024
 
    int status, print_len, is_continue = TRUE;
    int buf_len;
    uint8_t buf[BUF_LEN];
    struct user_regs_struct regs;
    poke_t poke;
    peek_t peek;

    g_bp.is_fresh = FALSE;
    
    /* Child has stopped in first instruction */
    wait (&status);

    /* Print initial information */
    ptrace (PTRACE_GETREGS, cpid, NULL, &regs);
    printf ("pid: %d\n"
            "eip: 0x%08lx\n"
            "esp: 0x%08lx\n"
            "ebp: 0x%08lx\n"
            "main: \n",
            cpid, regs.eip, regs.esp, regs.ebp);

    while (is_continue) {

#define CMD_ERR			-1
#define CMD_DISASS		0
#define CMD_CONTINUE	1
#define CMD_STEP		2
#define CMD_BREAKPOINT	3
#define CMD_QUIT		4
#define CMD_PEEK_M		5		/* Peek memory */
#define CMD_PEEK_R		6		/* Peek register */
#define CMD_POKE_M		7		/* Poke memory */
#define CMD_POKE_R		8		/* Poke register */
#define CMD_DISASS_SINGLE	9	/* Disassebly-single instruction */
#define CMD_UNSPPORTED	10
#define CMD_HELP		11


        buf_len = BUF_LEN;
        
        /* Parse user's input command */
        switch (parse_cmd (buf, &buf_len)) {
        case CMD_UNSPPORTED:
            printf ("Unspported command\n");
            break;
            
        case CMD_ERR:
            printf ("Error\n");
            break;

        case CMD_HELP:
            print_help ();
            break;

            /* Disassembly */
        case CMD_DISASS:
            disass (cpid, *((uint32_t*)buf));
            break;

        case CMD_DISASS_SINGLE:
            disass_single (cpid, *((uint32_t*)buf));
            break;

        case CMD_CONTINUE:
            ptrace (PTRACE_CONT, cpid, 0, 0);
            wait (&status);
            if (WIFEXITED(status)) {
                printf ("Program exits normally\n\n");
                break;
            } else if (WIFSTOPPED (status)) {
                if (handle_bp (cpid, g_bp) < 0)
                    printf ("Failed to handle breakpoint 0x%08X\n", g_bp.addr);
                else disass_single (cpid, g_bp.addr);
            }
            break;

        case CMD_STEP:
            ptrace (PTRACE_SINGLESTEP, cpid, 0, 0);
            wait (&status);
            ptrace (PTRACE_GETREGS, cpid, NULL, &regs);
            disass_single (cpid, regs.eip);
            break;

        case CMD_BREAKPOINT:
            if (insert_bp (cpid, *((uint32_t*)buf), &g_bp) < 0)
                printf ("Failed ");
            else
                printf ("Succeed ");
            printf ("to insert breakpoint on 0x%08X\n", *((uint32_t*)buf));
            break;

        case CMD_QUIT:
            is_continue = FALSE;
            printf("Quit\n");
            break;

        case CMD_PEEK_M:
            memcpy (&peek, buf, sizeof (peek_t));
            
            buf_len = max (peek.len, 1);
            if ('x' == peek.format || 0 == peek.format)
                buf_len *= 4;
            else if ('s' == peek.format)
                buf_len = BUF_LEN;
            buf_len = min (buf_len, BUF_LEN);

            if (-1 == peek_m (cpid, peek.addr, buf, &buf_len)) {
                printf ("Failed to read memory (0x%08X)\n",
                        peek.addr);
                break;
            }

            if ('s' == peek.format) {
                printf ("%s\n", buf);
                break;
            }

            if (peek.format != 'b' && peek.format != 'x' && peek.format != 0) {
                printf ("Unsupported format\n");
                break;
            }

            print_len = 0;
            while (print_len < buf_len) {
                if (print_len % 16 == 0)
                    printf ("0x%08x:\t", peek.addr + print_len);

                if ('b' == peek.format) {
                    printf (" %02X", *(buf + print_len));
                    print_len++;
                } else {
                    printf (" %08X", *(uint32_t*)(buf + print_len));
                    print_len += 4;
                }

                if (print_len % 16 == 0) {
                    printf ("\n");
                    continue;
                }

                if (print_len % 8 == 0)
                    printf (" ");
            }
            if (print_len % 16 != 0)
                printf ("\n");

            break;

        case CMD_PEEK_R:
            memcpy (&peek, buf, sizeof (peek_t));

            ptrace (PTRACE_GETREGS, cpid, NULL, &regs);
            
            if (!strncmp (peek.reg, "$regs", strlen ("$regs"))) {
                printf ("eip: 0x%08lX\n"
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
            } else if (!strncmp (peek.reg, "$esp", strlen ("$esp")))
                printf ("esp: 0x%08lX\n", regs.esp);
            else if (!strncmp (peek.reg, "$eip", strlen ("$eip")))
                printf ("eip: 0x%08lX\n", regs.eip);
            else if (!strncmp (peek.reg, "$ebp", strlen ("$ebp")))
                printf ("ebp: 0x%08lX\n", regs.ebp);
            else if (!strncmp (peek.reg, "$eax", strlen ("$eax")))
                printf ("eax: 0x%08lX\n", regs.eax);
            else printf ("Sorry, this register is not spported.\n");
            break;

        case CMD_POKE_M:
            memcpy (&poke, buf, sizeof (poke_t));

            if (ptrace (PTRACE_POKEDATA, cpid, poke.addr, poke.value) == -1)
                printf ("Failed to alter memory (0x%08X)", poke.addr);
            break;

        case CMD_POKE_R:
            memcpy (&poke, buf, sizeof (poke_t));

            ptrace (PTRACE_GETREGS, cpid, NULL, &regs);

            if (!strncmp (poke.reg, "$esp", strlen ("$esp")))
                regs.esp = poke.value;
            else if (!strncmp (poke.reg, "$ebp", strlen ("$ebp")))
                regs.ebp = poke.value;
            else if (!strncmp (poke.reg, "$eip", strlen ("$eip")))
                regs.eip = poke.value;
            else if (!strncmp (poke.reg, "$eax", strlen ("$eax")))
                regs.eax = poke.value;
            else {
                printf ("Sorry, this register is not spported.\n");
                break;
            }

            if (-1 == ptrace (PTRACE_SETREGS, cpid, NULL, &regs))
                printf ("Failed to alter register\n");            
            break;

        default:
            ;
        }

        /* wait (&status); */
    }

    ptrace (PTRACE_KILL, cpid, 0, 0);
 
    return 0;
}	

int parse_cmd (uint8_t *buf, int *len)
{
    static char last_cmd[BUF_LEN] = "";
    char input[BUF_LEN] = "", split[8] = " ", *para;
    int cmd = CMD_ERR;

    print_prefix();
    fgets (input, BUF_LEN, stdin);

    /* Repeat last command */
    if ('\n' == input[0]) {
        strcpy (input, last_cmd);
    } else
        /* Store this command */
        strcpy (last_cmd, input);

    para = strtok (input, split);
    if (!para)
        return cmd;

    if (0 == strncmp (para, "help", strlen ("help")))
        return CMD_HELP;
    /* Dissassebly */
    else if ((0 == strncmp (para, "disass", strlen ("disass")))
        || (0 == strncmp (para, "disassembly", strlen ("disassembly")))) {
        para = strtok (NULL, split);
        if (para && (*len >= sizeof(uint32_t))){
            *len = sizeof(uint32_t);

            /* Invalid address */
            if (0 == (*(uint32_t*)buf = strtoul (para, NULL, 0))) {
                printf ("Invalid address\n");
                return cmd;
            }
 		
            cmd = CMD_DISASS;
        }
        return cmd;

        /* Continue */
    } else if ((!strncmp (para, "c", strlen("c")))
               || (!strncmp (para, "continue", strlen("continue")))) {
        cmd = CMD_CONTINUE;
        return cmd;

    } else if ((!strncmp (para, "s", strlen("s")))
               || (!strncmp (para, "step", strlen("setp")))) {
        cmd = CMD_STEP;
        return cmd;

        /* Quit */
    } else if (!strncmp (para, "q", strlen("q"))){
        cmd = CMD_QUIT;
        return cmd;
        
        /* Set breakpoint */
    } else if (!strncmp (para, "b", strlen("b"))
               || !strncmp (para, "breakpoint", strlen("breakpoint"))) {
        para = strtok (NULL, split);
        if (para && (*len >= sizeof(uint32_t))){
            *len = sizeof(uint32_t);

            /* Invalid address */
            if (0 == (*(uint32_t*)buf = strtoul (para, NULL, 0))) {
                printf ("Invalid address\n");
                return cmd;
            }
 		
            cmd = CMD_BREAKPOINT;
        }
        return cmd;
        
        /* Peek memory or register */
    } else if (!strncmp (para, "peek", strlen ("peek"))) {
        char *parse;
        peek_t *peek;

        if (*len < sizeof (peek_t)) {
            printf ("Memory is not enough\n");
            return cmd;
        }

        peek = (peek_t *)buf;
        memset (peek, 0, sizeof (peek_t));
        parse = para + strlen ("peek");

        para = strtok (NULL, split);
        if (NULL == para) 
            return cmd;
 	
        if ('/' == *parse) {
            parse++;
            if (isdigit (*parse))
                peek->len = strtoul (parse, NULL, 0);

            parse = para - 1;
            while (*parse != '/' && !isalpha (*parse)) parse--;

            if (*parse != '/')
                peek->format = *parse;
            else return cmd;
        }

        if (isdigit (*para)) {
            if (0== (peek->addr = strtoul (para, NULL, 16)))
                return cmd;
            cmd = CMD_PEEK_M;
        } else if ('$' == *para) {
            cmd = CMD_PEEK_R;
            strncpy (peek->reg, para, sizeof (peek->reg)-1);
        }

        return cmd;
        
    } else if (!strncmp (para, "poke", strlen ("poke"))) {
        poke_t *poke;

        if (*len < sizeof (peek_t)) {
            printf ("Memory is not enough\n");
            return cmd;
        }

        poke = (poke_t *)buf;

        strcpy (split, " =");
        para = strtok (NULL, split);
        if (!para)
            return cmd;

        if (isdigit (*para)) {
            if (0== (poke->addr = strtoul (para, NULL, 0)))
                return cmd;
            cmd = CMD_POKE_M;
        } else if ('$' == *para) {
            cmd = CMD_POKE_R;
            strncpy (poke->reg, para, sizeof(poke->reg)-1);
        }

        para = strtok (NULL, split);
        if (!para) {
            cmd = CMD_ERR;
            return cmd;
        }

        if (0== (poke->value = strtoul (para, NULL, 0))) {
            cmd = CMD_ERR;
            return cmd;
        }

        return cmd;
    }

    return CMD_UNSPPORTED;
}


/* Print instruction */
int print_insn (x86_insn_t *insn)
{
    char buf[BUF_LEN] = "";
    int i;

    printf ("0x%08x:\t", insn->addr);

#define PRINT_WIDTH	7
    
    for (i = 0; i < PRINT_WIDTH; i++)
        if (i < insn->size) 
            printf("%02X ", insn->bytes[i]);
        else
            printf("   ");

    x86_format_insn(insn, buf, BUF_LEN, att_syntax);
    printf("\t%s\n", buf);
    fflush (stdout);

    return 0;
}

#define INSN_RET	(0xC3)
#define INSN_HALT	(0xF4)
int disass (pid_t cpid, uint32_t addr)
{
    uint8_t raw_data[BUF_LEN] = "\xc3";
    int data_len,   /* Len for raw_data */
        cur_pos,	/* Current position in raw_data */
        insn_len,	/* Size of instruction */
        ret_flag,	/* GET RET instruction */
        halt_addr,	/* Halt instruction's address */
        insn_num;
    x86_insn_t insn;/* Instruction */
    uint32_t start_addr;

    start_addr = addr;

    /* Don't stop print :) */
print_insn_loop:

    ret_flag = FALSE;
    halt_addr = 0;
    cur_pos = 0;
    data_len = BUF_LEN;
    insn_num = 0;

    /* Get raw data of instruction from addr */
    if (peek_m (cpid, start_addr, raw_data, &data_len) < 0) {
        printf ("Failed to read memory\n");
        return -1;
    }		

    x86_init(opt_none, NULL, NULL);
    while (insn_num < 50 && cur_pos < data_len) {
        /* Parse these instructions */
        insn_len = x86_disasm (raw_data, data_len, 0, cur_pos, &insn);
        if (insn_len) {
            /* print instruction */
            insn.addr = start_addr + cur_pos;
            insn.offset = 0;
            print_insn (&insn);
            cur_pos += insn_len;

            insn_num++;
        } else 
            /* Invalid instruction */
            cur_pos++;

        if (1 == insn_len) {
            if (INSN_RET == raw_data[cur_pos - 1]) { /* RET */
                /* Stop loop !!! */
                ret_flag = TRUE;
                break;
            } else if (INSN_HALT == raw_data[cur_pos - 1]) {
                /* HALT */
                halt_addr = insn.addr;
            }
        }
    } /* while ( cur_pos < data_len ) */

    x86_cleanup();

    if (halt_addr) 
        printf("[!!!!!!] Haha :D ===== Halt has been captured. "
               "Its address is 0x%08X.\n", halt_addr);

    if (FALSE == ret_flag) {
        char tmp_char;
        char clear_input;
 	
        printf ("[!!!!!!] Go on? ([Yy]/[Nn]) : ");
        tmp_char = getchar ();

        /* Clear all input */
        do
            clear_input = getchar ();
        while (clear_input != '\n');

        if (('y' == tmp_char) || ('Y' == tmp_char)) {
            /* Continue to disassembly */
            start_addr += cur_pos;			

            goto print_insn_loop;
        }
    }
 
    return 0;
}

int disass_single (pid_t cpid, uint32_t addr)
{
    uint8_t raw_data[BUF_LEN] = "\xc3";
    int data_len,			/* Len for raw_data */
        insn_len = 0;		/* Size of instruction */
    x86_insn_t insn;	/* Instruction */

    data_len = BUF_LEN;

    /* Get raw data of instruction from addr */
    if (peek_m (cpid, addr, raw_data, &data_len) < 0) {
        printf ("Failed to read memory\n");
        return -1;
    }		

    x86_init(opt_none, NULL, NULL);

    /* Parse these instructions */
    insn_len = x86_disasm (raw_data, data_len, 0, 0, &insn);
    if (insn_len) {
        /* print instruction */
        insn.addr = addr;
        insn.offset = 0;
        print_insn (&insn);
    } else
        printf ("Invalid instruction\n");

    x86_cleanup();

    return 0;
}

int peek_m (pid_t pid, uint32_t addr, uint8_t *buf, int *len)
{
    int peek_len = 0;
    uint32_t word;

    while (peek_len < *len) {
        word = (int32_t)ptrace (PTRACE_PEEKDATA, pid, addr + peek_len, NULL);
        if (-1 == word)
            break;

        if (peek_len < (*len & ~0x03))
            *(uint32_t *)(buf + peek_len) = word;
        else {
            int i;
            uint8_t *tmp = (uint8_t*)&word;
            for (i = 0; i < (*len & 0x03); i++) 
                *(buf + peek_len + i) = *(tmp + i);
            peek_len += i;
            break;
        }
        peek_len += 4;
    }

    if (0 == peek_len)
        return -1;
 
    *len = peek_len;

    return 0;
}

int print_help ()
{
    printf ("\ndwbugger's command:\n\n"
            "s/step:\n\t"
            "Single step\n"
            "c/continue:\n\t"
            "Continue the stoped program\n"
            "q/quit:\n\t"
            "Quit the program\n"
            "disass/disassembly <address>:\n\t"
            "Disassembly address's machine code\n"
            "peek/[len][format flag] <memory address or register>:\n\t"
            "Show the value of memory or register\n"
            "poke <memory address or register> = <value>:\n\t"
            "Alter the value of memory or register\n\n");

    return 0;
}

int print_prefix()
{
    printf("dWbugger > ");

    return 0;
}

int insert_bp (pid_t cpid, uint32_t addr, bp_t *bp)
{
    int tmp;

    if (TRUE == bp->is_fresh)
        if (ptrace (PTRACE_POKEDATA, cpid, bp->addr, bp->orig_data) == -1)
            return -1;
        
    /* Initialize bp */
    memset (bp, 0, sizeof (bp_t));

    tmp = ptrace (PTRACE_PEEKDATA, cpid, addr, NULL);
    if (-1 == tmp)
        return -1;

    /* Store original data */
    bp->orig_data = tmp;
    
    /* int 3 */
    if (ptrace (PTRACE_POKEDATA, cpid, addr, (tmp & ~0xFF) | 0xCC) == -1)
        return -1;

    bp->is_fresh = TRUE;
    bp->addr = addr;

    return 0;
}

int handle_bp (pid_t cpid, bp_t bp)
{
    struct user_regs_struct reg;

    if (bp.is_fresh != TRUE)
        return -1;

    /* Restore reg.eip */
    ptrace (PTRACE_GETREGS, cpid, NULL, &reg);
    if (bp.addr != reg.eip-1)   /* They're not matched. */
        return 0;

    printf ("Stopped by breatpoint 0x%08X\n", bp.addr);
    
    reg.eip = bp.addr;

    /* Restore data and eip */
    if ((ptrace (PTRACE_SETREGS, cpid, NULL, &reg) == -1)
        || (ptrace (PTRACE_POKEDATA, cpid, bp.addr, bp.orig_data) == -1)) {
        return -1;
    }
    
    /* This breakpoint has been used now */
    bp.is_fresh = FALSE;

    return 0;
}
