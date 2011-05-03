#ifndef __PARSE_CMD_H__
#define __PARSE_CMD_H__ 1



/* Parse parameters got from commandline */
int parse_cmdl(int argc, char **argv, int *data);

/* Parse user command */
int parse_cmd(uint8_t *buf, size_t *len);


#endif /* __PARSE_CMD_H__ */

