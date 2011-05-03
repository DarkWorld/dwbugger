CC= gcc

LIB_DIR = .


LIBFLAGS = -L$(LIB_DIR) -ldisasm
#LIBFLAGS = -Ldisasm
SFLAGS = -static
CFLAGS = -Wall -std=c99 -g


GOAL = dwbugger traced
OBJ = main.o parse.o cmd.o common.o peek_poke.o disas.o

all: $(GOAL)

dwbugger: $(OBJ)
	$(CC) $(CFLAGS) $(SFLAGS) $(OBJ) -o dwbugger $(LIBFLAGS)

main.o: parse.h cmd.h

parse.o: parse.h cmd.h

cmd.o: cmd.h disas.h

disas.o: disas.h


%.o: common.h


.PHONY: clean

clean:
	-rm -f *.o *~ *.gch $(GOAL)
