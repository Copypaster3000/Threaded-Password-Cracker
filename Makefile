#Makefile
#Drake Wheeler

CC = gcc
DEBUG = -g -DNOISY_DEBUG
CFLAGS =  -Wall -Wextra -Wshadow -Wunreachable-code -Wredundant-decls -Wmissing-declarations -Wold-style-definition \
		 -Wmissing-prototypes -Wdeclaration-after-statement -Wno-return-local-addr -Wunsafe-loop-optimizations \
		 -Wuninitialized -Werror -Wno-unused-parameter
LDFLAGS = -lcrypt


PROG1 = thread_hash
PROGS = $(PROG1)

#soucrse files
SRCS = thread_hash.c
#objcet file 
OBJS = $(SRCS:.c=.o)

all: $(PROGS)

$(PROG1): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

$(PROG1).o: $(PROG1).c
	$(CC) $(CFLAGS) -c $(PROG1).c -o $(PROG1).o

#adds -g for debug compile and -DNOISY_DEBUG to the compile flags for program to define the macro at compile time
#and print out the debug statements while the program is running
debug: CFLAGS += $(DEBUG)
debug: all


clean cls:
	rm -f $(PROGS) *.o *~ \#*
