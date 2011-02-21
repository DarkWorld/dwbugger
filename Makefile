CC= gcc

LIB_DIR = .


LIBFLAGS = -L$(LIB_DIR) -ldisasm
#LIBFLAGS = -Ldisasm
SFLAGS = -static
CFLAGS = -Wall -ansi -g 


GOAL = dwbugger traced
OBJ = main.o

all: $(GOAL)

dwbugger: $(OBJ)
	$(CC) $(CFLAGS) $(SFLAGS) $(OBJ) -o dwbugger $(LIBFLAGS)

main.o: common.h portable_ptrace.h libdis.h


.PHONY: clean

clean:
	-rm -f *.o *~ $(GOAL)
