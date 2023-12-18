PROG ?= finder
DEFS ?= -liot-base-nossl -llua -liot-json
EXTRA_CFLAGS ?= -Wall -Werror
CFLAGS += $(DEFS) $(EXTRA_CFLAGS)

all: $(PROG)

SRCS = main.c finder.c

$(PROG):
	$(CC) $(SRCS) $(CFLAGS) -o $@


clean:
	rm -rf $(PROG) *.o
